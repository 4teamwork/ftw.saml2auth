from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
from plone import api
from unittest import TestCase


class FunctionalTestCase(TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']

        # Enable the plugin by default
        self.enable_plugin()

    def enable_plugin(self):
        api.portal.set_registry_record(
            'enabled', True, interface=IServiceProviderSettings)

    def disable_plugin(self):
        api.portal.set_registry_record(
            'enabled', False, interface=IServiceProviderSettings)
