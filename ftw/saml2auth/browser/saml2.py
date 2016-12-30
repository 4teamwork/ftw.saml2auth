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
from ftw.saml2auth.config import STATUS_SUCCESS
from datetime import datetime, timedelta
from dm.saml2.util import xs_convert_from_xml
from zope.component import getMultiAdapter
from pyxb import BadDocumentError

import base64
import dm.xmlsec.binding as xmlsec
import uuid
import zlib
import logging
import pytz

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
            return self.process_saml_response()

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
            raise BadRequest('Missing SAMLResponse')

        doc = self.request.form['SAMLResponse']
        try:
            doc = base64.b64decode(doc)
        except TypeError:
            raise BadRequest('Undecodable SAMLResponse')

        settings = self.sp_settings()
        sign_context = SignatureContext()
        key = xmlsec.Key.loadMemory(
            settings.idp_cert, xmlsec.KeyDataFormatCertPem, None)
        sign_context.add_key(key, settings.idp_issuer_id)
        try:
            resp = CreateFromDocument(doc, context=sign_context)
        except BadDocumentError, e:
            raise BadRequest('Invalid SAMLResponse')
        except VerifyError, e:
            logger.warning('Signature verification error: %s' % str(e))
            raise BadRequest('Invalid Signature')

        # Verify destination of SAML response
        portal_state = getMultiAdapter(
            (self.context, self.request), name=u'plone_portal_state')
        sp_url = '{}/saml2/sp/sso'.format(portal_state.portal_url())
        if resp.Destination != sp_url:
            logger.warning('Wrong destination in SAML response. Got %s, '
                           'expected %s' % (resp.Destination, sp_url))
            raise BadRequest('Wrong destination')

        status = resp.Status.StatusCode.Value
        if status != STATUS_SUCCESS:
            # Status code may contain a second-level status code.
            if resp.Status.StatusCode.StatusCode:
                status += ': ' + resp.Status.StatusCode.StatusCode.Value

            logger.warning('Failed SAML2 request with status code: %s.'
                           % status)
            raise Unauthorized()

        # Verfiy issue time of response.
        now = datetime.utcnow()
        issue_instant = resp.IssueInstant.astimezone(
            tz=pytz.utc).replace(tzinfo=None)
        delta = timedelta(seconds=settings.max_clock_skew)
        if (now + delta) < issue_instant or (now - delta) > issue_instant:
            logger.warning('Clock skew too great.')
            raise Unauthorized()

        # We expect the subject and attributes in the first assertion
        if len(resp.Assertion) > 0:
            assertion = resp.Assertion[0]
            if not assertion.verified_signature():
                raise BadRequest('Unsigned Assertion')
            subject = assertion.Subject.NameID.value().encode('utf8')
            attributes = extract_attributes(assertion)
            return "subject: %s; attributes: %s" % (subject, attributes)
            #self._logins.insert(subject)
        else:
            logger.warning('Missing assertion')
            raise Unauthorized()
        return "Process SAML 2 repsonse"

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
        req.Issuer = saml.Issuer(settings.sp_issuer_id)
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
            sign_context.add_key(key, settings.sp_issuer_id)
            req.request_signature(context=sign_context)

        return req.toxml()

    def sp_settings(self):
        registry = queryUtility(IRegistry)
        return registry.forInterface(IServiceProviderSettings)

    def saml2_response(self):
        """Build a SAML2 response."""
