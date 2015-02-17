import unittest
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
from ftw.saml2auth.tests.utils import get_data
from zope.publisher.browser import TestRequest
from base64 import b64encode
from dm.saml2.signature import SignatureContext
from dm.xmlsec.binding import Key, KeyDataFormatPem
from dm.saml2.pyxb.protocol import CreateFromDocument
from pyxb.binding.datatypes import dateTime
from pyxb.utils.utility import UTCOffsetTimeZone


class TestSaml2WebSSOExtraction(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.plugin = self.portal.acl_users['saml2_websso']

    def sign_response(self, resp, update_issueinstant=True):
        ctx = SignatureContext()
        key = Key.loadMemory(get_data('signing.key'), KeyDataFormatPem)
        ctx.add_key(key, self.plugin.issuer_id)
        if update_issueinstant:
            resp.IssueInstant = dateTime.utcnow().replace(
                tzinfo=UTCOffsetTimeZone())
        if resp.Assertion:
            resp.Assertion[0].Signature = None
            resp.Assertion[0].request_signature(
                keyname=self.plugin.issuer_id, context=ctx)
        else:
            resp.Signature = None
            resp.request_signature(keyname=self.plugin.issuer_id, context=ctx)
        return resp

    def test_no_credentials_without_saml_response(self):
        req = TestRequest()
        self.assertEqual({}, self.plugin.extractCredentials(req))

    def test_no_credentials_with_invalid_saml_response(self):
        req = TestRequest(form={'SAMLResponse': 'Invalid SAML Response'})
        self.assertEqual({}, self.plugin.extractCredentials(req))

    def test_no_credentials_with_invalid_signature(self):
        req = TestRequest(form={
            'SAMLResponse': b64encode(get_data('resp_success.xml'))})
        self.assertEqual({}, self.plugin.extractCredentials(req))

    def test_credentials_from_successful_response(self):
        resp = CreateFromDocument(get_data('resp_success.xml'),
                                  suppress_verification=True)
        resp = self.sign_response(resp)
        req = TestRequest(form={'SAMLResponse': b64encode(resp.toxml())})
        creds = self.plugin.extractCredentials(req)
        self.assertIn('subject', creds)
        self.assertEqual('jim@domain.local', creds['subject'])
        self.assertIn('attributes', creds)
        self.assertEqual('Jim Raynor', creds['attributes']['fullname'])

    def test_no_credentials_with_wrong_destination(self):
        resp = CreateFromDocument(get_data('resp_success.xml'),
                                  suppress_verification=True)
        resp.Destination = u'https://www.google.com'
        resp = self.sign_response(resp)
        req = TestRequest(form={'SAMLResponse': b64encode(resp.toxml())})
        self.assertEqual({}, self.plugin.extractCredentials(req))

    def test_no_credentials_with_unsuccessful_status(self):
        resp = CreateFromDocument(get_data('resp_invalid.xml'),
                                  suppress_verification=True)
        resp = self.sign_response(resp)
        req = TestRequest(form={'SAMLResponse': b64encode(resp.toxml())})
        self.assertEqual({}, self.plugin.extractCredentials(req))

    def test_no_credentials_with_old_response(self):
        resp = CreateFromDocument(get_data('resp_success.xml'),
                                  suppress_verification=True)
        resp = self.sign_response(resp, update_issueinstant=False)
        req = TestRequest(form={'SAMLResponse': b64encode(resp.toxml())})
        self.assertEqual({}, self.plugin.extractCredentials(req))
