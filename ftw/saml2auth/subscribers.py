from ftw.saml2auth.interfaces import IServiceProviderSettings
from netaddr import IPAddress
from netaddr import IPSet
from plone.registry.interfaces import IRegistry
from zope.component import adapter
from zope.component import queryMultiAdapter
from zope.component import queryUtility
from zope.component.hooks import getSite
from ZPublisher.interfaces import IPubBeforeCommit


@adapter(IPubBeforeCommit)
def initiate_saml2_protocol_exchange(event):
    site = getSite()
    if site is None:
        return

    request = event.request
    response = request.response

    # Do not initiate for non-HTML content (e.g. ressources)
    content_type = response.getHeader('Content-Type')
    if not content_type or not content_type.startswith('text/html'):
        return

    portal_state = queryMultiAdapter(
        (site, request), name=u'plone_portal_state')

    # Do not initiate if user is already authenticated.
    if portal_state is None or not portal_state.anonymous():
        return

    registry = queryUtility(IRegistry)
    settings = registry.forInterface(IServiceProviderSettings, check=False)

    # Do not initiate if SAML2 authentication is disabled.
    if not settings.enabled:
        return

    # Do not initiate if user accesses outside of the internal network
    internal_network_ips = IPSet(settings.internal_network)
    current_ip = IPAddress(request.getClientAddr())
    if current_ip not in internal_network_ips:
        return

    # Do not initiate if coming from IdP to prevent endless loop
    if request.getHeader('HTTP_REFERER') == settings.idp_url:
        return

    current_url = request['ACTUAL_URL']
    portal_url = portal_state.portal_url()
    acs_url = u'{}/saml2/sp/sso'.format(portal_url.decode('utf8'))

    # Do not initiate if calling our SAML2 endpoint
    if current_url == acs_url:
        return

    # Allow logout and manual login and reset password
    if (current_url.endswith('/logged_out') or
            current_url.endswith('/login') or
            current_url.endswith('/mail_password_form') or
            current_url.endswith('/mail_password') or
            'portal_registration/' in current_url):
        return

    # Replace current response with a form containing a SAML2 authentication
    # request.
    form_properties = queryMultiAdapter((site, request),
                                        name='saml2_form_properties')()
    response = request.response
    response.headers = {}
    response.accumulated_headers = []
    response.setBody(
        ' '.join(FORM_TEMPLATE.format(
            action=form_properties.get('action'),
            authn_request=form_properties.get('authn_request'),
            relay_state=form_properties.get('relay_state'),
        ).split()))
    response.setHeader('Expires', 'Sat, 01 Jan 2000 00:00:00 GMT')
    response.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')


FORM_TEMPLATE = """
<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="x-ua-compatible" content="ie=edge">
    </head>
    <body onLoad="document.forms[0].submit();" style="visibility: hidden;">
        <form action="{action}" method="POST">
            <input type="hidden" name="SAMLRequest" value="{authn_request}">
            <input type="hidden" name="RelayState" value="{relay_state}">
            <span>If you are not automaticallly redirected click</span>
            <input type="submit" value="Continue">
        </form>
    </body>
</html>
"""
