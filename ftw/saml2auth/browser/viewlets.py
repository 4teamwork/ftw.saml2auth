from base64 import b64encode
from ftw.saml2auth.interfaces import IAuthNRequestStorage
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.utils import create_authn_request
from netaddr import AddrFormatError
from netaddr import IPAddress
from netaddr import IPSet
from plone.app.layout.viewlets.common import ViewletBase
from plone.registry.interfaces import IRegistry
from zope.component import queryUtility


class SAML2SSOAutoSubmitViewlet(ViewletBase):
    """A Viewlet that injects a Javascript snippet which replaces the body of
       the page with a form containing an AuthNRequest. The form is
       automatically submitted to the IdP url."""

    def render(self):

        # Do not render snippet if the user is authenticated.
        if not self.portal_state.anonymous():
            return ''

        registry = queryUtility(IRegistry)
        settings = registry.forInterface(IServiceProviderSettings)

        # Do not render snippet if SAML2 authentication is disabled.
        if not settings.enabled:
            return ''

        # Do not render snippet if coming from IdP to prevent endless loop
        if self.request.getHeader('HTTP_REFERER') == settings.idp_url:
            return ''

        current_url = self.request['ACTUAL_URL']
        query_string = self.request['QUERY_STRING']
        acs_url = u'{}/saml2/sp/sso'.format(
            self.portal_state.portal_url().decode('utf8'))

        # Do not render snippet for our SAML2 endpoint to prevent endless loops
        if current_url == acs_url:
            return ''

        # Allow logout and manual login
        if (current_url.endswith('/logged_out') or
                current_url.endswith('/login')):
            return ''

        # Internal or external AuthN context?
        ips = settings.internal_network or ''
        try:
            ipset = IPSet(ips.split(','))
        except AddrFormatError:
            ipset = IPSet()
        try:
            ip = IPAddress(self.request.getClientAddr())
        except AddrFormatError:
            ip = IPAddress('127.0.0.1')
        if ip in ipset:
            authn_context = settings.internal_authn_context
        else:
            authn_context = settings.authn_context

        # Create AuthNRequest
        req = create_authn_request(
            idp_url=settings.idp_url,
            acs_url=acs_url,
            issuer_id=settings.sp_issuer_id,
            nameid_format=settings.nameid_format,
            authn_context=authn_context,
            signing_key=settings.signing_key,
            )

        # Store id of AuthNRequest with current url.
        issued_requests = IAuthNRequestStorage(self.portal_state.portal())
        if query_string:
            current_url = '{}?{}'.format(current_url, query_string)
        issued_requests.add(req.ID, current_url)

        # Prevent HTTP caching
        self.request.response.setHeader(
            'Cache-Control', 'no-cache, no-store, must-revalidate')

        return ' '.join(JS_TEMPLATE.format(form=FORM_TEMPLATE.format(
            action=settings.idp_url,
            authn_request=b64encode(req.toxml()),
            )).split())


JS_TEMPLATE = """
<script type="text/javascript">
    document.addEventListener("DOMContentLoaded", function(event) {{
        document.querySelector("body").innerHTML='{form}';
        document.querySelector("#saml2-sso").submit();
    }});
</script>
"""


FORM_TEMPLATE = """
<form id="saml2-sso" action="{action}" method="POST" style="display:none;">
  <input type="hidden" name="SAMLRequest" value="{authn_request}">
  <input type="submit" value="Login">
</form>
"""
