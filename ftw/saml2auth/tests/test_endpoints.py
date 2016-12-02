from ftw.saml2auth.browser.saml2 import Saml2View
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
from ftw.saml2auth.tests.utils import get_data
from plone.registry.interfaces import IRegistry
from xml.etree.ElementTree import fromstring
from zExceptions import BadRequest
from zope.component import queryUtility
import base64
import unittest


class TestAuthnRequest(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        registry = queryUtility(IRegistry)
        self.settings = registry.forInterface(IServiceProviderSettings)
        self.settings.idp_url = u'https://idp.example.org/saml2/idp/sso'
        self.settings.issuer_id = u'https://sp.example.org/'

    def authnrequest(self):
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        return fromstring(s2view.authn_request())

    def test_authnrequest_attributes(self):
        req = self.authnrequest()
        self.assertEqual(u'http://nohost/plone/saml2/sp/sso',
                         req.get('AssertionConsumerServiceURL'))
        self.assertEqual(u'https://idp.example.org/saml2/idp/sso',
                         req.get('Destination'))
        self.assertEqual(u'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                         req.get('ProtocolBinding'))

    def test_authnrequest_issuer(self):
        req = self.authnrequest()
        issuer = req.find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text
        self.assertEqual('https://sp.example.org/',
                         issuer)

    def test_authnrequest_nameidpolicy(self):
        req = self.authnrequest()
        nameid_format = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy').get('Format')
        self.assertEqual(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            nameid_format)

        self.settings.nameid_format = u'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        req = self.authnrequest()
        nameid_format = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy').get('Format')
        self.assertEqual(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            nameid_format)

    def test_authnrequest_authn_context(self):
        req = self.authnrequest()
        authn_context = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext').find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef').text
        self.assertEqual(
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            authn_context)

        self.settings.authn_context = u'urn:federation:authentication:windows'
        req = self.authnrequest()
        authn_context = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext').find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef').text
        self.assertEqual(
            u'urn:federation:authentication:windows',
            authn_context)

    def test_signed_authnrequest_contains_signature(self):
        self.settings.sign_authnrequest = True
        self.settings.signing_key = get_data('signing.key').decode('utf8')
        req = self.authnrequest()
        self.assertIsNotNone(
            req.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))

    def test_unsigned_authnrequest_doesnt_contain_signature(self):
        self.settings.sign_authnrequest = False
        req = self.authnrequest()
        self.assertIsNone(
            req.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))


class TestExtractAuthnRequest(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']

    def test_authenticated_extract_from_request(self):
        doc = get_data('authnrequest.xml').decode('utf8')
        self.layer['request'].form.update({'SAMLRequest': base64.b64encode(doc)})
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        req, rs = s2view.extract_authn_request()
        self.assertEqual('_6c0dd1ea-0475-49aa-97fa-128824946622', req.ID)
        self.assertEqual('', rs)

    def test_authenticated_extract_from_request_with_relaystate(self):
        doc = get_data('authnrequest.xml').decode('utf8')
        self.layer['request'].form.update({
            'SAMLRequest': base64.b64encode(doc),
            'RelayState': 'token',
        })
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        req, rs = s2view.extract_authn_request()
        self.assertEqual('_6c0dd1ea-0475-49aa-97fa-128824946622', req.ID)
        self.assertEqual('token', rs)

    def test_extract_from_invalid_request_raises_badrequest(self):
        self.layer['request'].form.update({'SAMLRequest': 'invalid'})
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        with self.assertRaises(BadRequest):
            req, rs = s2view.extract_authn_request()
