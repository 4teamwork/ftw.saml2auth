from ZPublisher.interfaces import IPubBeforeCommit
from base64 import b64encode
from ftw.saml2auth.interfaces import IAuthNRequestStorage
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.utils import create_authn_request
from plone.registry.interfaces import IRegistry
from zope.component import adapter
from zope.component import queryMultiAdapter
from zope.component import queryUtility
from zope.component.hooks import getSite
import urllib


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
    settings = registry.forInterface(IServiceProviderSettings)

    # Do not initiate if SAML2 authentication is disabled.
    if not settings.enabled:
        return

    # Do not initiate if coming from IdP to prevent endless loop
    if request.getHeader('HTTP_REFERER') == settings.idp_url:
        return

    current_url = request['ACTUAL_URL']
    query_string = request['QUERY_STRING']
    portal_url = portal_state.portal_url()
    acs_url = u'{}/saml2/sp/sso'.format(portal_url.decode('utf8'))

    # Do not initiate if calling our SAML2 endpoint
    if current_url == acs_url:
        return

    # Allow logout and manual login
    if (current_url.endswith('/logged_out') or
            current_url.endswith('/login')):
        return

    # Create AuthNRequest
    req = create_authn_request(
        idp_url=settings.idp_url,
        acs_url=acs_url,
        issuer_id=settings.sp_issuer_id,
        nameid_format=settings.nameid_format,
        authn_context=settings.authn_context,
        authn_context_comparison=settings.authn_context_comparison,
        signing_key=settings.signing_key,
        )

    # Include query string in current url
    if query_string:
        current_url = '{}?{}'.format(current_url, query_string)

    # Store id of AuthNRequest with current url.
    if settings.store_requests:
        issued_requests = IAuthNRequestStorage(site)
        issued_requests.add(req.ID, current_url)
        relay_state = ''
    else:
        # Store current url in RelayState
        relay_state = urllib.quote(current_url[len(portal_url):])

    # Replace current response with a form containing a SAML2 authentication
    # request.
    response = request.response
    response.headers = {}
    response.accumulated_headers = []
    response.setBody(
        ' '.join(FORM_TEMPLATE.format(
            action=settings.idp_url,
            authn_request=b64encode(req.toxml()),
            relay_state=relay_state,
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
