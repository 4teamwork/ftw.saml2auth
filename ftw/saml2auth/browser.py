import uuid
from Acquisition import aq_inner
from base64 import b64encode
from Products.CMFCore.utils import getToolByName
from Products.Five import BrowserView
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from DateTime import DateTime
from netaddr import IPSet
from netaddr import IPAddress
from netaddr import AddrFormatError


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
          <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
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
        )
        return b64encode(' '.join(req.split()))

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
        if self.request.getHeader('Referer', '') == self.plugin.idp_url:
            return ""
        return """<script type="text/javascript">
        jQuery(function($){$('#login_form_internal input[name="submit"]').click();});
        </script>
        """
