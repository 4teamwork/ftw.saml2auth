from ftw.saml2auth.interfaces import IAuthNRequestStorage
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.settings import saml2_settings
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from plone import api
from plone.memoize.instance import memoize
from plone.registry.interfaces import IRegistry
from Products.Five import BrowserView
from zope.component import queryUtility
import urllib


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

        return OneLogin_Saml2_Authn_Request(saml2_settings())

    def _get_base64_encoded_authn_request(self):
        authn_request = self._get_authn_request()
        if authn_request is None:
            return ''
        return authn_request.get_request(deflate=False)

    def _get_relay_state(self):
        authn_request = self._get_authn_request()
        if not authn_request:
            return ''

        current_url = self._get_current_url()

        # Store id of AuthNRequest with current url.
        if self.settings.store_requests:
            issued_requests = IAuthNRequestStorage(api.portal.get())
            issued_requests.add(authn_request.get_id(), current_url)
            relay_state = ''
        else:
            # Store current url in RelayState
            relay_state = urllib.quote(current_url[len(self.portal_url):])

        return relay_state

    def _get_current_url(self):
        if 'came_from' in self.request.form:
            return self.request.form.get('came_from')

        current_url = self.request['ACTUAL_URL']

        if current_url.split('/')[-1] in ['login', 'logged_out']:
            return self.portal_url

        query_string = self.request['QUERY_STRING']

        # Include query string in current url
        if query_string:
            current_url = '{}?{}'.format(current_url, query_string)

        return current_url
