from plone.app.layout.viewlets.common import ViewletBase
from ftw.saml2auth.interfaces import IServiceProviderSettings
from zope.component import queryUtility
from plone.registry.interfaces import IRegistry
from base64 import b64encode
from zope.component import getMultiAdapter


class SAML2SSOAutoSubmitViewlet(ViewletBase):
    """"""

    def render(self):
        if not self.portal_state.anonymous():
            return ''

        registry = queryUtility(IRegistry)
        settings = registry.forInterface(IServiceProviderSettings)

        if not settings.enabled:
            return ''

        if self.request.getHeader('HTTP_REFERER') == settings.idp_url:
            return ''

        saml2view = getMultiAdapter(
            (self.portal_state.portal(), self.request), name="saml2")

        return ' '.join(JS_TEMPLATE.format(form=FORM_TEMPLATE.format(
            action=settings.idp_url,
            authn_request=b64encode(saml2view.authn_request()),
            relay_state="12345",
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
  <input type="hidden" name="RelayState" value="{relay_state}">
  <input type="submit" value="Login">
</form>
"""
