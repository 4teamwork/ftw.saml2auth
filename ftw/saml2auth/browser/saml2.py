from AccessControl import Unauthorized
from DateTime import DateTime
from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from Products.PlonePAS.events import UserInitialLoginInEvent
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from base64 import b64encode
from datetime import datetime, timedelta
from dm.saml2.pyxb import assertion as saml
from dm.saml2.pyxb import protocol as samlp
from dm.saml2.pyxb.protocol import CreateFromDocument
from dm.saml2.pyxb.protocol import Response
from dm.saml2.signature import SignatureContext, VerifyError
from dm.saml2.util import xs_convert_from_xml
from ftw.saml2auth.config import STATUS_SUCCESS
from ftw.saml2auth.errors import SAMLResponseError
from ftw.saml2auth.interfaces import IAuthNRequestStorage
from ftw.saml2auth.interfaces import IIdentityProviderSettings
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.utils import create_authn_request
from plone import api
from plone.memoize.instance import memoize
from plone.registry.interfaces import IRegistry
from pyxb import BadDocumentError
from pyxb.bundles.wssplat import ds
from pyxb.utils.domutils import BindingDOMSupport
from zExceptions import BadRequest
from zExceptions import NotFound as zNotFound
from zope import event
from zope.component import getMultiAdapter
from zope.component import queryUtility
from zope.interface import implements
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces import NotFound

import base64
import dm.xmlsec.binding as xmlsec
import logging
import pytz
import urllib
import zlib

COOKIE_NAME = '_ftwsaml2auth'

BindingDOMSupport.DeclareNamespace(samlp.Namespace, 'samlp')
BindingDOMSupport.DeclareNamespace(saml.Namespace, 'saml')
BindingDOMSupport.DeclareNamespace(ds.Namespace, 'ds')

logger = logging.getLogger('ftw.saml2auth')


def quote(s):
    return s.replace('%', '%25').replace('&', '%26')


def unquote(s):
    return s.replace('%26', '&').replace('%25', '%')


def extract_attributes(assertion):
    """Return a dict of the attributes in the given assertion."""
    attrs = {}
    for astmt in assertion.AttributeStatement:
        for attr in astmt.Attribute:
            key = attr.Name.encode('utf8')
            value = xs_convert_from_xml(
                attr.AttributeValue, ty='string')
            if value:
                value = value.encode('utf8')
            attrs[key] = value
    return attrs


class Saml2FormProperties(BrowserView):
    """ Returns all properties required to create a saml-authentication-form.

    Example usage:

    <tal:saml define="portal context/@@plone_portal_state/portal;
                      properties portal/@@saml2_form_properties;"
              condition="properties/enabled">

        <form id="login_form_internal"
              tal:attributes="action properties/action"
              method="POST">

            <input type="hidden" name="SAMLRequest" value="properties/authn_request" />
            <input type="hidden" name="RelayState" value="properties/relay_state" />
            <input type="submit" name="submit" value="Log in"/>
        </form>
    </tal:saml>
    """
    def __init__(self, context, request):
        super(Saml2FormProperties, self).__init__(context, request)
        self.settings = queryUtility(IRegistry).forInterface(IServiceProviderSettings)
        self.portal_url = api.portal.get().absolute_url()

    def __call__(self):
        return {
            'enabled': self._is_enabled(),
            'action': self._get_action(),
            'authn_request': self._get_base64_encoded_authn_request(),
            'relay_state': self._get_relay_state(),
            }

    def _is_enabled(self):
        return self.settings.enabled

    def _get_action(self):
        return self.settings.idp_url

    @memoize
    def _get_authn_request(self):
        if not self._is_enabled():
            return None

        return create_authn_request(
            idp_url=self.settings.idp_url,
            acs_url=u'{}/saml2/sp/sso'.format(self.portal_url.decode('utf8')),
            issuer_id=self.settings.sp_issuer_id,
            nameid_format=self.settings.nameid_format,
            authn_context=self.settings.authn_context,
            authn_context_comparison=self.settings.authn_context_comparison,
            signing_key=self.settings.signing_key,
            )

    def _get_base64_encoded_authn_request(self):
        authn_request = self._get_authn_request()
        if not authn_request:
            return ''

        return b64encode(authn_request.toxml())

    def _get_relay_state(self):
        authn_request = self._get_authn_request()
        if not authn_request:
            return ''

        current_url = self.request['ACTUAL_URL']
        query_string = self.request['QUERY_STRING']

        # Include query string in current url
        if query_string:
            current_url = '{}?{}'.format(current_url, query_string)

        # Store id of AuthNRequest with current url.
        if self.settings.store_requests:
            issued_requests = IAuthNRequestStorage(self.portal.get())
            issued_requests.add(authn_request.ID, current_url)
            relay_state = ''
        else:
            # Store current url in RelayState
            relay_state = urllib.quote(current_url[len(self.portal_url):])

        return relay_state


class Saml2View(BrowserView):
    """Endpoints for SAML 2.0 Web SSO"""

    implements(IPublishTraverse)

    request_form = ViewPageTemplateFile('request_form.pt')
    response_form = ViewPageTemplateFile('response_form.pt')
    saml_response = ViewPageTemplateFile('response.pt', content_type='text/xml')

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
            return self.process_saml_request()
        elif self.party == 'sp':
            try:
                return self.process_saml_response()
            except SAMLResponseError as exc:
                response = self.request.response
                response.setHeader('Content-Type', 'text/plain')
                response.setStatus(400, lock=1)
                response.setBody(exc.message, lock=1)

    def extract_authn_request(self):
        """Extract AuthNRequest and RelayState from the HTTP request or cookie.
        """
        authn_request = None
        relay_state = ''
        if 'SAMLRequest' in self.request.form:
            try:
                authn_request = base64.b64decode(
                    self.request.form['SAMLRequest'])
            except TypeError:
                raise BadRequest()
            if 'RelayState' in self.request.form:
                relay_state = self.request.form['RelayState']

        if self.mtool.isAnonymousUser():
            if authn_request is None:
                raise BadRequest()

            # Store AuthNRequest in a cookie
            cookie_value = base64.b64encode(zlib.compress(
                '&'.join([quote(authn_request), quote(relay_state)])))
            self.request.response.setCookie(COOKIE_NAME, cookie_value, path='/')
            self.request.response.redirect(self.context.absolute_url())
            raise Unauthorized()

        # Get AuthNRequest from cookie
        if authn_request is None:
            if COOKIE_NAME not in self.request.cookies:
                raise BadRequest()
            try:
                values = zlib.decompress(base64.b64decode(
                    self.request.cookies[COOKIE_NAME])).split('&')
            except (zlib.error, TypeError):
                raise BadRequest()
            authn_request = unquote(values[0])
            if len(values) > 1:
                relay_state = unquote(values[1])

        req = CreateFromDocument(authn_request)
        return (req, relay_state)

    def create_saml_response(self, req):
        member = self.mtool.getAuthenticatedMember()
        registry = queryUtility(IRegistry)
        settings = registry.forInterface(IIdentityProviderSettings)

        # Construct a SAML Response
        resp = Response(
            InResponseTo=req.ID,
        )

        now = DateTime()
        issuer_id = unicode(self.context.absolute_url())

        resp.Issuer = saml.Issuer(issuer_id)
        resp.Status = samlp.Status(samlp.StatusCode(
            Value=u'urn:oasis:names:tc:SAML:2.0:status:Success'))

        assertion = saml.Assertion()
        assertion.Issuer = saml.Issuer(issuer_id)

        assertion.Subject = saml.Subject()
        assertion.Subject.NameID = saml.NameID(
            member.getProperty(settings.nameid_property).decode('utf8'),
            Format=settings.nameid_format)
        assertion.Subject.SubjectConfirmation = [saml.SubjectConfirmation(
            saml.SubjectConfirmationData(
                InResponseTo=req.ID,
                NotOnOrAfter=(now + 1.0/24).HTML4(),
                Recipient=u'https://sp.example.com/test',
            ),
            Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")]

        assertion.Conditions = saml.Conditions(
            NotBefore=now.HTML4(),
            NotOnOrAfter=(now + 1.0/24).HTML4())
        assertion.Conditions.AudienceRestriction = [saml.AudienceRestriction(
            saml.Audience(u'https://sp.example.com/')
        )]

        assertion.AuthnStatement = [saml.AuthnStatement(
            saml.AuthnContext(saml.AuthnContextClassRef(
                u'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')),
            AuthnInstant=now.HTML4(),
            SessionIndex=assertion.ID,
        )]

        assertion.AttributeStatement = [saml.AttributeStatement()]
        assertion.AttributeStatement[0].append(
            saml.Attribute(
                saml.AttributeValue(u'jim@domain.local'),
                Name=u'email',
            )
        )
        assertion.AttributeStatement[0].append(
            saml.Attribute(
                saml.AttributeValue(u'Jim Raynor'),
                Name=u'fullname',
            )
        )

        resp.Assertion = [assertion]

        # Sign assertion
        sign_context = SignatureContext()
        key = xmlsec.Key.loadMemory(
            settings.idp_signing_key, xmlsec.KeyDataFormatPem, None)
        sign_context.add_key(key, issuer_id)
        assertion.request_signature(context=sign_context)

        return resp

    def process_saml_request(self):
        """Process a SAMLRequest and return SAMLResponse."""
        req, relay_state = self.extract_authn_request()

        # TODO: check if req is allowed

        resp = self.create_saml_response(req)
        self.request.response.setHeader('Content-Type', 'text/xml')
        return resp.toxml()

        return self.response_form(
            action='https://sp.example.com/SAML2/SSO/POST',
            response=resp.toxml().encode('base64'),
            relay_state='token',
        )

    def process_saml_response(self):
        """Extract the SAML response from the request and authenticate the
           user.
        """

        if 'SAMLResponse' not in self.request.form:
            raise SAMLResponseError('Missing SAMLResponse')

        doc = self.request.form['SAMLResponse']
        try:
            doc = base64.b64decode(doc)
        except TypeError:
            raise SAMLResponseError('Undecodable SAMLResponse')

        settings = self.sp_settings()
        sign_context = SignatureContext()
        key = xmlsec.Key.loadMemory(
            settings.idp_cert, xmlsec.KeyDataFormatCertPem, None)
        sign_context.add_key(key, settings.idp_issuer_id)
        try:
            resp = CreateFromDocument(doc, context=sign_context)
        except BadDocumentError, e:
            raise SAMLResponseError('Invalid SAMLResponse')
        except VerifyError, e:
            logger.warning('Signature verification error: %s' % str(e))
            raise SAMLResponseError('Invalid Signature')

        portal_state = getMultiAdapter(
            (self.context, self.request), name=u'plone_portal_state')
        portal_url = portal_state.portal_url()

        if settings.store_requests:
            # Verify InResponseTo attribute and get asscoiated url to redirect
            # to
            issued_requests = IAuthNRequestStorage(portal_state.portal())
            url = issued_requests.pop(resp.InResponseTo)
            if not url:
                raise SAMLResponseError('Unknown SAMLResponse')
        else:
            # Get destination url from RelayState
            url = portal_url + urllib.unquote(
                self.request.form.get('RelayState', ''))

        # Verify destination of SAML response
        sp_url = '{}/saml2/sp/sso'.format(portal_state.portal_url())
        if resp.Destination != sp_url:
            logger.warning('Wrong destination in SAML response. Got %s, '
                           'expected %s' % (resp.Destination, sp_url))
            raise SAMLResponseError('Wrong destination')

        # Verify that response has status success.
        status = resp.Status.StatusCode.Value
        if status != STATUS_SUCCESS:
            # Status code may contain a second-level status code.
            if resp.Status.StatusCode.StatusCode:
                status += ': ' + resp.Status.StatusCode.StatusCode.Value

            logger.warning('Failed SAML2 request with status code: %s.'
                           % status)
            raise SAMLResponseError('Wrong status')

        # Verfiy issue time of response.
        now = datetime.utcnow()
        issue_instant = resp.IssueInstant.astimezone(
            tz=pytz.utc).replace(tzinfo=None)
        delta = timedelta(seconds=settings.max_clock_skew)
        if (now + delta) < issue_instant or (now - delta) > issue_instant:
            logger.warning('Clock skew too great.')
            raise SAMLResponseError('Clock skew too great')

        # We expect the subject and attributes in the first assertion
        if len(resp.Assertion) > 0:
            assertion = resp.Assertion[0]
            if not assertion.verified_signature():
                raise SAMLResponseError('Unsigned Assertion')
            subject = assertion.Subject.NameID.value().encode('utf8')
            if settings.update_user_properties:
                attributes = extract_attributes(assertion)
            else:
                attributes = {}
            self.login_user(subject, attributes)
            self.request.response.redirect('%s' % url)
            return
        else:
            logger.warning('Missing assertion')
            raise SAMLResponseError('Missing assertion')

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
