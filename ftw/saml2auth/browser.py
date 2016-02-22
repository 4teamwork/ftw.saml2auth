from Acquisition import aq_inner
from DateTime import DateTime
from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from base64 import b64encode
from dm.xmlsec.binding.tmpl import Signature
from ftw.saml2auth.config import NSMAP, NS_DS
from lxml.etree import fromstring, tostring, XMLParser, XML
from netaddr import AddrFormatError
from netaddr import IPAddress
from netaddr import IPSet
from tempfile import NamedTemporaryFile
from xml.dom.minidom import parseString

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

        req = """
        <samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            ID="_%(id_)s"
                            AssertionConsumerServiceURL="%(acs_url)s"
                            IssueInstant="%(issue_instant)s">
          <saml:Issuer>%(issuer)s</saml:Issuer>
          <samlp:NameIDPolicy Format="%(nameid_policy)s"/>
          <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef>%(authn_context)s</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
        """ % dict(
            id_=uuid.uuid4(),
            issuer=self.plugin.sp_url,
            acs_url=self.request.form.get('came_from') or context.absolute_url(),
            issue_instant=DateTime().HTML4(),
            authn_context=authn_context,
            nameid_policy=self.plugin.nameid_policy,
        )

        # Remove whitespaces
        parser = XMLParser(remove_blank_text=True)
        req = tostring(XML(req, parser=parser))

        if self.plugin.sign_authnrequests:
            req = self.sign(req)

        return b64encode(req)

    def sign(self, xml):
        elem = fromstring(xml)
        signature = Signature(xmlsec.TransformExclC14N, xmlsec.TransformRsaSha1)
        issuer = elem.xpath('//saml:Issuer', namespaces=NSMAP)[0]
        issuer.addnext(signature)

        ref = signature.addReference(xmlsec.TransformSha1)
        ref.addTransform(xmlsec.TransformEnveloped)
        ref.addTransform(xmlsec.TransformExclC14N)

        key_info = signature.ensureKeyInfo()
        key_info.addX509Data()

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

        newdoc = parseString(tostring(elem))
        signature_nodes = newdoc.getElementsByTagName("Signature")
        for signature in signature_nodes:
            signature.removeAttribute('xmlns')
            signature.setAttribute('xmlns:ds', NS_DS)
            if not signature.tagName.startswith('ds:'):
                signature.tagName = 'ds:' + signature.tagName
            nodes = signature.getElementsByTagName("*")
            for node in nodes:
                if not node.tagName.startswith('ds:'):
                    node.tagName = 'ds:' + node.tagName

        return newdoc.saveXML(newdoc.firstChild)

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
