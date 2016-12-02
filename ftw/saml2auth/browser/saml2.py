from Acquisition import aq_inner
from AccessControl import Unauthorized
from DateTime import DateTime
from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from base64 import b64encode
from lxml.etree import fromstring, tostring, XMLParser, XML
from netaddr import AddrFormatError
from netaddr import IPAddress
from netaddr import IPSet
from tempfile import NamedTemporaryFile
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces import NotFound
from zope.interface import implements
from zExceptions import NotFound as zNotFound
from zExceptions import BadRequest
from dm.saml2.pyxb.protocol import CreateFromDocument
from dm.saml2.signature import SignatureContext, VerifyError
from dm.saml2.pyxb.protocol import Response
from dm.saml2.pyxb import protocol as samlp
from dm.saml2.pyxb import assertion as saml
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from pyxb.utils.domutils import BindingDOMSupport
from plone.registry.interfaces import IRegistry
from ftw.saml2auth.interfaces import IIdentityProviderSettings
from ftw.saml2auth.interfaces import IServiceProviderSettings
from zope.component import queryUtility
from pyxb.bundles.wssplat import ds

import base64
import dm.xmlsec.binding as xmlsec
import uuid
import zlib

BindingDOMSupport.DeclareNamespace(samlp.Namespace, 'samlp')
BindingDOMSupport.DeclareNamespace(saml.Namespace, 'saml')
BindingDOMSupport.DeclareNamespace(ds.Namespace, 'ds')


def quote(s):
    return s.replace('%', '%25').replace('&', '%26')


def unquote(s):
    return s.replace('%26', '&').replace('%25', '%')


def create_authnrequest_cookie(authn_request, relay_state):
    value = '%s&%s' % (quote(authn_request), quote(relay_state))

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
        # self.plugin = None

        # acl_users = getToolByName(self, "acl_users")
        # plugins = acl_users._getOb('plugins')
        # extractors = plugins.listPlugins(IExtractionPlugin)
        # for extractor_id, extractor in extractors:
        #     if extractor.meta_type == "Saml2 Web SSO plugin":
        #         self.plugin = extractor
        #         break

        # self.is_internal_request = False
        # if self.plugin is not None:
        #     try:
        #         ipset = IPSet(self.plugin.internal_network.split(','))
        #     except AddrFormatError:
        #         ipset = IPSet()
        #     try:
        #         ip = IPAddress(self.request.getClientAddr())
        #     except AddrFormatError:
        #         ip = IPAddress('127.0.0.1')
        #     self.is_internal_request = ip in ipset

    def publishTraverse(self, request, name):
        # URL routing for SAML2 endpoints
        # /saml2/idp/sso -> SAML2 Response
        # /saml2/sp/sso ->
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
            return self.process_saml_response()

    def extract_authn_request(self):
        """Extract AuthNRequest and RelayState from the HTTP request."""
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
                '&'.join(quote(authn_request), quote(relay_state))))
            self.request.response.setCookie('_ftwsaml2auth', cookie_value, path='/')
            self.request.response.redirect(self.context.absolute_url())
            raise Unauthorized()

        # Get AuthNRequest from cookie
        if authn_request is None:
            if '_ftwsam2auth' not in self.request.cookies:
                raise BadRequest()
            try:
                values = zlib.uncompress(base64.b64decode(
                    self.request.cookies['_ftwsaml2auth'])).split('&')
            except (zlib.error, TypeError):
                raise BadRequest()
            authn_request = unquote(values[0])
            if len(values) > 1:
                relay_state = unquote(values[1])

        req = CreateFromDocument(authn_request)
        return (req, relay_state)

    def process_saml_request(self):
        """Process a SAMLRequest and return SAMLResponse."""
        req, relay_state = self.extract_authn_request()

        member = self.mtool.getAuthenticatedMember()
        registry = queryUtility(IRegistry)
        settings = registry.forInterface(IIdentityProviderSettings)

        # TODO: check if req is allowed

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

        sign_context = SignatureContext()
        key = xmlsec.Key.loadMemory(
            settings.idp_signing_key, xmlsec.KeyDataFormatPem, None)
        sign_context.add_key(key, issuer_id)

        assertion.request_signature(context=sign_context)

        self.request.response.setHeader('Content-Type', 'text/xml')
        return resp.toxml()

        return self.response_form(
            action='https://sp.example.com/SAML2/SSO/POST',
            response=resp.toxml().encode('base64'),
            relay_state='token',
        )

    def process_saml_response(self):
        print "Process SAML 2 repsonse"

    def authn_request(self):
        """Build an AuthNRequest."""
        registry = queryUtility(IRegistry)
        settings = registry.forInterface(IServiceProviderSettings)

        portal = getToolByName(self.context, 'portal_url').getPortalObject()
        acs_url = u'%s/saml2/sp/sso' % portal.absolute_url().decode('utf8')

        req = samlp.AuthnRequest(
            Destination=settings.idp_url,
            ProtocolBinding=u'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            AssertionConsumerServiceURL=acs_url
        )
        req.Issuer = saml.Issuer(settings.issuer_id)
        req.NameIDPolicy = samlp.NameIDPolicy(
            Format=settings.nameid_format,
        )
        req.RequestedAuthnContext = samlp.RequestedAuthnContext(
            saml.AuthnContextClassRef(settings.authn_context),
            Comparison="exact")

        if settings.sign_authnrequest:
            sign_context = SignatureContext()
            key = xmlsec.Key.loadMemory(
                settings.signing_key, xmlsec.KeyDataFormatPem, None)
            sign_context.add_key(key, settings.issuer_id)
            req.request_signature(context=sign_context)

        return req.toxml()

    def saml2_response(self):
        """Build a SAML2 response."""



    def sign(self, xml):
        doc = fromstring(xml)
        xmlsec.addIDs(doc, ["ID"])
        signature = xmlsec.findNode(doc, xmlsec.dsig("Signature"))

        dsig_ctx = xmlsec.DSigCtx()
        sign_key = xmlsec.Key.loadMemory(
            self.plugin.sp_key, xmlsec.KeyDataFormatPem, None)

        cert_file = NamedTemporaryFile(delete=True)
        cert_file.file.write(self.plugin.sp_cert)
        cert_file.file.flush()
        sign_key.loadCert(cert_file.name, xmlsec.KeyDataFormatCertPem)
        cert_file.close()

        dsig_ctx.signKey = sign_key
        dsig_ctx.sign(signature)

        return tostring(doc)

    def post_action(self):
        if self.plugin is None:
            return ''
        return self.plugin.idp_url

    def auto_submit(self):
        if self.request.get('URL', '').endswith('/logged_out'):
            return ""
        if not self.is_internal_request:
            return ""
        # Do not autosubmit if we already came from the IdP to prevent an
        # endless loop.
        if self.request.getHeader('Referer', '').startswith(self.plugin.idp_url):
            return ""
        return """<script type="text/javascript">
        jQuery(function($){$('#login_form_internal input[name="submit"]').click();});
        </script>
        """


AUTHNREQ_TMPL = """<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                       xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                       AssertionConsumerServiceURL="%(acs_url)s"
                                       Destination="%(destination)s"
                                       ID="_%(id_)s"
                                       IssueInstant="%(issue_instant)s"
                                       ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                       Version="2.0">
    <saml:Issuer>%(issuer)s</saml:Issuer>
    %(signature)s
    <samlp:NameIDPolicy Format="%(nameid_policy)s"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>%(authn_context)s</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"""

SIGNATURE_TMPL = """<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_%(id_)s">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue></ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue></ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data >
                <ds:X509Certificate/>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>"""
