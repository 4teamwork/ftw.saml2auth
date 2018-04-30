from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
from ftw.saml2auth.tests.utils import get_data
from plone.registry.interfaces import IRegistry
from unittest import TestCase
from zope.component import queryUtility


class IntegrationTestCase(TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']

        self.request.setServerURL(
            protocol='https', hostname='sp.domain.local', port='443')
        self.request.environ['HTTP_HOST'] = 'sp.domain.local'
        self.request.environ['SERVER_PORT'] = '443'

        # Configure SAML2 settings
        registry = queryUtility(IRegistry)
        self.settings = registry.forInterface(IServiceProviderSettings)
        self.settings.idp_cert = get_data('signing.crt').decode('utf8')
        self.settings.idp_issuer_id = u'http://fs.domain.local/adfs/services/trust'
        self.settings.idp_url = u'https://fs.domain.local/adfs/ls'
        self.settings.sp_issuer_id = u'https://sp.domain.local'
        self.settings.autoprovision_users = True
        self.settings.enabled = True
