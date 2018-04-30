from ftw.saml2auth.interfaces import IServiceProviderSettings
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from plone import api
from plone.registry.interfaces import IRegistry
from zope.component import queryUtility


def saml2_settings():
    registry = queryUtility(IRegistry)
    sp_settings = registry.forInterface(
        IServiceProviderSettings, check=False)
    portal_url = api.portal.get().absolute_url()

    authn_context = sp_settings.authn_context
    if not authn_context:
        authn_context = False

    settings_data = {
        "strict": True,
        "debug": False,
        "sp": {
            # Identifier of the SP entity  (must be a URI)
            "entityId": sp_settings.sp_issuer_id,
            "assertionConsumerService": {
                # URL Location where the Response from the IdP will be returned
                "url": u'{}/saml2/sp/sso'.format(portal_url.decode('utf8')),
                # SAML protocol binding to be used when returning the Response
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            # Specifies the constraints on the name identifier to be used to
            # represent the requested subject.
            "NameIDFormat": sp_settings.nameid_format,
            "x509cert": sp_settings.signing_cert or '',
            "privateKey": sp_settings.signing_key or '',
        },
        "idp": {
            # Identifier of the IdP entity  (must be a URI)
            "entityId": sp_settings.idp_issuer_id,
            "singleSignOnService": {
                # URL Target of the IdP where the Authentication Request
                # Message will be sent.
                "url": sp_settings.idp_url,
                # SAML protocol binding to be used when returning the Response
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            # Public x509 certificate of the IdP
            "x509cert": sp_settings.idp_cert or '',
        },
        "security": {
            "requestedAuthnContext": authn_context,
            "requestedAuthnContextComparison": sp_settings.authn_context_comparison,
        }
    }
    return OneLogin_Saml2_Settings(settings_data)
