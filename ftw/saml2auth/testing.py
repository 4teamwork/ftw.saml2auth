from plone.app.testing import PloneSandboxLayer
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import IntegrationTesting, FunctionalTesting
from plone.app.testing import applyProfile
from plone.testing import z2
from zope.configuration import xmlconfig
from ftw.saml2auth.plugin import SAML2Plugin


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
        applyProfile(portal, 'ftw.saml2auth:default')

        # Setup PAS plugin
        uf = portal.acl_users
        plugin = SAML2Plugin('saml2')
        uf._setObject(plugin.getId(), plugin)
        plugin = uf['saml2']
        plugin.manage_activateInterfaces([
            'IRolesPlugin',
            'IUserEnumerationPlugin',
        ])


FTW_SAML2AUTH_FIXTURE = FtwSaml2authLayer()
FTW_SAML2AUTH_INTEGRATION_TESTING = IntegrationTesting(
    bases=(FTW_SAML2AUTH_FIXTURE,), name="ftw.saml2auth:Integration")
FTW_SAML2AUTH_FUNCTIONAL_TESTING = FunctionalTesting(
    bases=(FTW_SAML2AUTH_FIXTURE,), name="ftw.saml2auth:Functional")
