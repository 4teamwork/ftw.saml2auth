from DateTime import DateTime
from ftw.saml2auth.errors import SAMLResponseError
from ftw.saml2auth.interfaces import IAuthNRequestStorage
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.settings import saml2_settings
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.errors import OneLogin_Saml2_ValidationError
from onelogin.saml2.response import OneLogin_Saml2_Response
from plone.registry.interfaces import IRegistry
from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView
from Products.PlonePAS.events import UserInitialLoginInEvent
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from urlparse import urlparse
from zExceptions import NotFound as zNotFound
from zope import event
from zope.component import getMultiAdapter
from zope.component import queryUtility
from zope.interface import implements
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces import NotFound

import logging
import urllib

logger = logging.getLogger('ftw.saml2auth')


class Saml2View(BrowserView):
    """Endpoints for SAML 2.0 Web SSO"""

    implements(IPublishTraverse)

    def __init__(self, context, request):
        super(Saml2View, self).__init__(context, request)
        self.party = None
        self.service = None
        self.mtool = getToolByName(self.context, 'portal_membership')

    def publishTraverse(self, request, name):
        # URL routing for SAML2 endpoints
        # /saml2/idp/sso -> Process AuthNRequest and issue SAMLResponse
        # /saml2/sp/sso -> Process SAMLResponse and authenticate user
        if self.party is None:
            if name in {'idp', 'sp'}:
                self.party = name
            else:
                raise NotFound(self, name, request)
        elif self.service is None:
            if name != 'sso':
                raise NotFound(self, name, request)
            self.service = name
        return self

    def __call__(self):
        if self.party is None or self.service is None:
            raise zNotFound()

        if self.party == 'idp':
            # Not implemented yet
            raise zNotFound()
        elif self.party == 'sp':
            try:
                return self.process_saml_response()
            except SAMLResponseError as exc:
                response = self.request.response
                response.setHeader('Content-Type', 'text/plain')
                response.setStatus(400, lock=1)
                response.setBody(exc.message, lock=1)

    def process_saml_response(self):
        """Extract the SAML response from the request and authenticate the
           user.
        """

        if 'SAMLResponse' not in self.request.form:
            raise SAMLResponseError('Missing SAMLResponse')

        saml_repsonse_data = self.request.form['SAMLResponse']
        try:
            saml_response = OneLogin_Saml2_Response(
                saml2_settings(), saml_repsonse_data)
        except TypeError as exc:
            logger.warning(exc.__str__())
            raise SAMLResponseError(str(exc))

        purl = urlparse(self.request.getURL())

        req_data = {
            'https': 'on' if purl.scheme == 'https' else 'off',
            'http_host': purl.hostname,
            'server_port': purl.port,
            'script_name': purl.path,
            'get_data': self.request.form,
            # Needed if using ADFS as IdP
            # https://github.com/onelogin/python-saml/pull/144
            'lowercase_urlencoding': True,
            'post_data': {},
        }

        try:
            saml_response.is_valid(req_data, raise_exceptions=True)
        except OneLogin_Saml2_ValidationError as exc:
            logger.warning(exc.__str__())
            raise SAMLResponseError(exc.message)
        except OneLogin_Saml2_Error as exc:
            logger.warning(exc.__str__())
            raise SAMLResponseError('SAML2 Error')


        settings = self.sp_settings()
        portal_state = getMultiAdapter(
            (self.context, self.request), name=u'plone_portal_state')
        portal_url = portal_state.portal_url()

        if settings.store_requests:
            # Verify InResponseTo attribute and get asscoiated url to redirect
            # to
            issued_requests = IAuthNRequestStorage(portal_state.portal())
            in_response_to = saml_response.document.get('InResponseTo', None)
            url = issued_requests.pop(in_response_to)
            if not url:
                raise SAMLResponseError('Unknown SAMLResponse')
        else:
            # Get destination url from RelayState
            url = portal_url + urllib.unquote(
                self.request.form.get('RelayState', ''))

        userid = saml_response.get_nameid()
        attributes = {
            k: v[0] for k, v in saml_response.get_attributes().items()
        }
        self.login_user(userid, attributes)
        self.request.response.redirect('%s' % url)
        return

    def login_user(self, userid, properties):
        uf = getToolByName(self.context, 'acl_users')
        mtool = getToolByName(self, 'portal_membership')
        member = mtool.getMemberById(userid)

        settings = self.sp_settings()
        if member is None and settings.autoprovision_users:
            plugins = uf._getOb('plugins')
            enumerators = plugins.listPlugins(IUserEnumerationPlugin)
            plugin = None
            for id_, enumerator in enumerators:
                if enumerator.meta_type == "ftw.saml2auth plugin":
                    plugin = enumerator
                    break
            if plugin is None:
                logger.warning(
                    'Missing PAS plugin. Cannot autoprovision user %s.' % userid)
                return

            plugin.addUser(userid)
            member = mtool.getMemberById(userid)

        # Setup session
        uf.updateCredentials(
            self.request, self.request.response, userid, '')

        # Update login times and other member properties
        first_login = False
        default = DateTime('2000/01/01')
        login_time = member.getProperty('login_time', default)
        if login_time == default:
            first_login = True
            login_time = DateTime()
        member.setMemberProperties(dict(
            login_time=mtool.ZopeTime(),
            last_login_time=login_time,
            **properties
        ))

        # Fire login event
        user = member.getUser()
        if first_login:
            event.notify(UserInitialLoginInEvent(user))
        else:
            event.notify(UserLoggedInEvent(user))

        # Expire the clipboard
        if self.request.get('__cp', None) is not None:
            self.request.response.expireCookie('__cp', path='/')

        # Create member area
        mtool.createMemberArea(member_id=userid)

    def sp_settings(self):
        registry = queryUtility(IRegistry)
        return registry.forInterface(IServiceProviderSettings)
