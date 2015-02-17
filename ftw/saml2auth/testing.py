from plone.app.testing import PloneSandboxLayer
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import IntegrationTesting, FunctionalTesting
from plone.testing import z2
from zope.configuration import xmlconfig
from ftw.saml2auth.plugin import Saml2WebSSOPlugin
from ftw.saml2auth.tests.utils import get_data


class FtwSaml2authLayer(PloneSandboxLayer):

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        # Load ZCML
        import ftw.saml2auth
        xmlconfig.file('configure.zcml',
                       ftw.saml2auth,
                       context=configurationContext)
        z2.installProduct(app, 'ftw.saml2auth')

    def setUpPloneSite(self, portal):
        # Setup PAS plugin
        uf = portal.acl_users
        plugin = Saml2WebSSOPlugin('saml2_websso')
        uf._setObject(plugin.getId(), plugin)
        plugin = uf['saml2_websso']
        plugin.manage_activateInterfaces([
            'IAuthenticationPlugin',
            'IExtractionPlugin',
            'IRolesPlugin',
            'IUserEnumerationPlugin',
        ])
        plugin.idp_url = 'https://fs.domain.local/adfs/ls/'
        plugin.sp_url = 'https://sp.domain.local'
        plugin.issuer_id = 'http://fs.domain.local/adfs/services/trust'
        plugin.signing_cert = get_data('signing.crt')


FTW_SAML2AUTH_FIXTURE = FtwSaml2authLayer()
FTW_SAML2AUTH_INTEGRATION_TESTING = IntegrationTesting(
    bases=(FTW_SAML2AUTH_FIXTURE,), name="ftw.saml2auth:Integration")
FTW_SAML2AUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_SAML2AUTH_FIXTURE,), name="ftw.saml2auth:Functional")
