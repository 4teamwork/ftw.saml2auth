from Acquisition import aq_inner
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

import dm.xmlsec.binding as xmlsec
import uuid


class Saml2View(BrowserView):
    """Create a SAML 2.0 AuthRequest"""

    def __init__(self, context, request):
        super(Saml2View, self).__init__(context, request)
        self.plugin = None

        acl_users = getToolByName(self, "acl_users")
        plugins = acl_users._getOb('plugins')
        extractors = plugins.listPlugins(IExtractionPlugin)
        for extractor_id, extractor in extractors:
            if extractor.meta_type == "Saml2 Web SSO plugin":
                self.plugin = extractor
                break

        self.is_internal_request = False
        if self.plugin is not None:
            try:
                ipset = IPSet(self.plugin.internal_network.split(','))
            except AddrFormatError:
                ipset = IPSet()
            try:
                ip = IPAddress(self.request.getClientAddr())
            except AddrFormatError:
                ip = IPAddress('127.0.0.1')
            self.is_internal_request = ip in ipset

    def authn_request(self):
        context = aq_inner(self.context)
        if self.plugin is None:
            return ''

        authn_context = self.plugin.authn_context
        if self.is_internal_request:
            authn_context = self.plugin.internal_authn_context

        id_ = uuid.uuid4()

        signature = ''
        if self.plugin.sign_authnrequests:
            signature = SIGNATURE_TMPL % dict(id_=id_)

        req = AUTHNREQ_TMPL % dict(
            id_=id_,
            issuer=self.plugin.sp_url,
            acs_url=self.request.form.get('came_from') or context.absolute_url(),
            issue_instant=DateTime().HTML4(),
            authn_context=authn_context,
            nameid_policy=self.plugin.nameid_policy,
            signature=signature,
        )

        # Remove whitespaces
        parser = XMLParser(remove_blank_text=True)
        req = tostring(XML(req, parser=parser))

        if self.plugin.sign_authnrequests:
            req = self.sign(req)

        return b64encode(req)

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
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
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
                <ds:X509SubjectName/>
                <ds:X509IssuerSerial/>
                <ds:X509Certificate/>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>"""
