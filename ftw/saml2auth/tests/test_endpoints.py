from freezegun import freeze_time
from ftw.saml2auth.browser.saml2 import Saml2View
from ftw.saml2auth.errors import SAMLResponseError
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.tests import IntegrationTestCase
from ftw.saml2auth.tests.utils import get_data
from plone.registry.interfaces import IRegistry
from zope.component import queryUtility
import base64


class TestProcessSAMLResponse(IntegrationTestCase):

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']
        self.request._steps = []
        self.request.setServerURL(
            protocol='https', hostname='sp.domain.local', port='443')
        self.request.environ['HTTP_HOST'] = 'sp.domain.local'
        self.request.environ['SERVER_PORT'] = '443'
        registry = queryUtility(IRegistry)
        self.settings = registry.forInterface(IServiceProviderSettings)
        self.settings.idp_cert = get_data('signing.crt').decode('utf8')
        self.settings.idp_issuer_id = u'http://fs.domain.local/adfs/services/trust'
        self.settings.idp_url = u'https://fs.domain.local/adfs/ls'
        self.settings.sp_issuer_id = u'https://sp.domain.local'
        self.settings.autoprovision_users = True

    def test_request_without_saml_response_raises(self):
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Missing SAMLResponse', cm.exception.message)

    def test_undecodeable_saml_response_raises(self):
        self.request.form.update({'SAMLResponse': 'invalid'})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual("Incorrect padding", cm.exception.message)

    def test_invalid_saml_response_raises(self):
        self.request.form.update({
            'SAMLResponse': base64.b64encode('<response>invalid</response>')})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Unsupported SAML version', cm.exception.message)

    @freeze_time("2015-02-12 15:33:56")
    def test_saml_response_without_signature_raises(self):
        saml_response = get_data('resp_unsigned.xml')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(saml_response)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual(
            'No Signature found. SAML Response rejected', cm.exception.message)

    @freeze_time("2015-02-12 15:33:56")
    def test_invalid_signature_raises(self):
        saml_response = get_data('resp_invalid_sig.xml')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(saml_response)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual(
            'Signature validation failed. SAML Response rejected',
            cm.exception.message)

    @freeze_time("2015-02-12 15:33:56")
    def test_unknown_in_response_to_raises(self):
        self.settings.store_requests = True
        saml_response = get_data('resp_unknown.xml')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(saml_response)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Unknown SAMLResponse', cm.exception.message)

    @freeze_time("2015-02-12 15:33:56")
    def test_wrong_destination_raises(self):
        saml_response = get_data('resp_wrong_destination.xml')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(saml_response)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual(
            'The response was received at https://sp.domain.local instead of '
            'https://sp.wrong.one', cm.exception.message)

    @freeze_time("2015-02-12 15:33:56")
    def test_valid_saml_response_authenticates_user(self):
        saml_response = get_data('resp_success.xml')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(saml_response)})
        s2view = Saml2View(self.portal, self.request)
        s2view.process_saml_response()
        self.assertIn(
            'jim@domain.local',
            base64.b64decode(self.request.response.cookies['__ac']['value']))
