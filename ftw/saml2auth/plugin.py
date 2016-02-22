from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.requestmethod import postonly
from App.class_init import default__class_init__ as InitializeClass
from BTrees.OIBTree import OITreeSet
from DateTime import DateTime
from OFS.Cache import Cacheable
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.interfaces.plugins import (
    IAuthenticationPlugin,
    IExtractionPlugin,
    IRolesPlugin,
    IUserEnumerationPlugin
)
from Products.PlonePAS.events import UserLoggedInEvent
from Products.PlonePAS.events import UserInitialLoginInEvent
from datetime import datetime, timedelta
from dm.saml2.pyxb.protocol import CreateFromDocument
from dm.saml2.signature import SignatureContext, VerifyError
from dm.saml2.util import xs_convert_from_xml
from dm.xmlsec.binding import Key, KeyDataFormatCertPem
from zope import event
from zope.interface import implements
import base64
import logging
import pytz

STATUS_SUCCESS = u'urn:oasis:names:tc:SAML:2.0:status:Success'
AUTHN_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
INTERNAL_AUTHN_CONTEXT = 'urn:federation:authentication:windows'
NAMEID_POLICY = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

logger = logging.getLogger('ftw.saml2auth')

manage_addSaml2WebSSOPlugin = PageTemplateFile(
    "www/addPlugin",
    globals(),
    __name__="manage_addSaml2WebSSOPlugin",
)


def addSaml2WebSSOPlugin(self, id_, title='', REQUEST=None):
    """Add a Saml2 Web SSO plugin to a Pluggable Authentication Service.
    """
    p = Saml2WebSSOPlugin(id_, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace?manage_tabs_message=Saml2+Web+SSO+plugin+"
            "added." % self.absolute_url())


class Saml2WebSSOPlugin(BasePlugin):
    """Saml2 Web SSO authentication plugin using HTTP POST binding.
    """
    implements(
        IAuthenticationPlugin,
        IExtractionPlugin,
        IRolesPlugin,
        IUserEnumerationPlugin
    )

    meta_type = "Saml2 Web SSO plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},)
        + BasePlugin.manage_options
        + Cacheable.manage_options
    )

    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title

        self.idp_url = None
        self.sp_url = None
        self.sp_key = None
        self.sp_cert = None
        self.sign_authnrequests = False
        self.idp_cert = None
        self.issuer_id = None
        self.clock_skew = 60
        self.nameid_policy = NAMEID_POLICY
        self.authn_context = AUTHN_CONTEXT
        self.internal_network = ''
        self.internal_authn_context = INTERNAL_AUTHN_CONTEXT

        self._roles = ()
        self._logins = OITreeSet()

    # IExtractionPlugin implementation
    def extractCredentials(self, request):

        creds = {}

        if 'SAMLResponse' in request.form:
            doc = request.form['SAMLResponse']
            try:
                doc = base64.b64decode(doc)
            except TypeError:
                return {}

            try:
                resp = CreateFromDocument(
                    doc,
                    context=self._signature_context(),
                )
            except VerifyError, e:
                logger.warning('Signature verification error: %s' % str(e))
                return {}

            if not resp.Destination.startswith(self.sp_url):
                logger.warning('Wrong destination in SAML response.')
                return {}

            status = resp.Status.StatusCode.Value
            if status != STATUS_SUCCESS:
                # Status code may contain a second-level status code.
                if resp.Status.StatusCode.StatusCode:
                    status += ': ' + resp.Status.StatusCode.StatusCode.Value

                logger.warning('Failed SAML2 request with status code: %s.'
                               % status)
                return {}

            # Verfiy issue time of response.
            now = datetime.utcnow()
            issue_instant = resp.IssueInstant.astimezone(
                tz=pytz.utc).replace(tzinfo=None)
            delta = timedelta(seconds=self.clock_skew)
            if (now + delta) < issue_instant or (now - delta) > issue_instant:
                logger.warning('Clock skew too great.')
                return {}

            # We expect the subject and attributes in the first assertion
            if len(resp.Assertion) > 0:
                assertion = resp.Assertion[0]
                subject = assertion.Subject.NameID.value().encode('utf8')
                attributes = self._extract_attributes(assertion)
                creds['subject'] = subject
                creds['attributes'] = attributes
                self._logins.insert(subject)
            else:
                logger.warning('Missing assertion')
                return {}

        return creds

    # IAuthenticationPlugin implementation
    def authenticateCredentials(self, credentials):

        # Ignore credentials that are not from our extractor
        extractor = credentials.get('extractor')
        if extractor != self.getId():
            return None

        # We need at least a login name
        login = credentials.get('subject')
        if not login:
            return None

        # Store credentials in a different plugin (session)
        self._getPAS().updateCredentials(self.REQUEST, self.REQUEST.RESPONSE,
                                         login, "")

        # Handle login related stuff
        self._loginUser(login)

        # Update properties
        mtool = getToolByName(self, 'portal_membership')
        member = mtool.getMemberById(login)
        properties = credentials.get('attributes', {})
        member.setMemberProperties(properties)

        return (login, login)

    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
                       sort_by=None, max_results=None, **kw):

        # Only return a user if an id or a login was provided.
        # We need this for updateCredentials of the default session plugin.

        if id and login and id != login:
            return None

        if (id and not exact_match) or kw:
            return None

        key = id and id or login

        if key not in self._logins:
            return None

        return [
            {
                "id": key,
                "login": key,
                "pluginid": self.getId(),
            }
        ]

    # IRolesPlugin
    def getRolesForPrincipal(self, principal, request=None):
        # Return a list of roles for the given principal (a user or group).
        if principal.getId() in self._logins:
            return self._roles

        return ()

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of Trusted Proxy Authentication Plugin.
        """
        response = REQUEST.response

        self.idp_url = REQUEST.form.get('idp_url')
        self.sp_url = REQUEST.form.get('sp_url')
        self.sp_key = REQUEST.form.get('sp_key')
        self.sp_cert = REQUEST.form.get('sp_cert')
        self.idp_cert = REQUEST.form.get('idp_cert')
        self.sign_authnrequests = bool(REQUEST.form.get('sign_authnrequests', False))
        self.issuer_id = REQUEST.form.get('issuer_id')
        self.clock_skew = int(REQUEST.form.get('clock_skew', 60))
        self.nameid_policy = REQUEST.form.get('nameid_policy')
        self.authn_context = REQUEST.form.get('authn_context')
        self.internal_network = REQUEST.form.get('internal_network')
        self.internal_authn_context = REQUEST.form.get(
            'internal_authn_context')

        roles = REQUEST.form.get('roles')
        self._roles = tuple([role.strip() for role in roles.split(',')])

        # Purge signature context
        self._signature_context(purge=True)

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))

    def roles(self):
        """Accessor for config form"""
        return ','.join(self._roles)

    security.declarePrivate('_loginUser')

    def _loginUser(self, login):
        """Handle login for the given user
        """
        mtool = getToolByName(self, 'portal_membership')
        user = mtool.getUser(login)
        member = mtool.getMemberById(login)

        # Set login times
        first_login = False
        default = DateTime('2000/01/01')
        login_time = member.getProperty('login_time', default)
        if login_time == default:
            first_login = True
            login_time = DateTime()
        member.setMemberProperties(dict(
            login_time=mtool.ZopeTime(),
            last_login_time=login_time
        ))

        # Fire login event
        if first_login:
            event.notify(UserInitialLoginInEvent(user))
        else:
            event.notify(UserLoggedInEvent(user))

        # Expire the clipboard
        if self.REQUEST.get('__cp', None) is not None:
            self.REQUEST.RESPONSE.expireCookie('__cp', path='/')

        # Create member area
        mtool.createMemberArea(member_id=login)

    def _signature_context(self, purge=False):
        context = getattr(self, '_v_signature_context', None)
        if purge or context is None:
            context = SignatureContext()
            key = Key.loadMemory(self.idp_cert, KeyDataFormatCertPem, None)
            context.add_key(key, self.issuer_id)
            setattr(self, '_v_signature_context', context)
        return context

    def _extract_attributes(self, assertion):
        attrs = {}
        for astmt in assertion.AttributeStatement:
            for attr in astmt.Attribute:
                key = attr.Name.encode('utf8')
                value = xs_convert_from_xml(
                    attr.AttributeValue, ty='string').encode('utf8')
                attrs[key] = value
        return attrs


InitializeClass(Saml2WebSSOPlugin)
