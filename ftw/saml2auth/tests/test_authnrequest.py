from ftw.saml2auth.tests.utils import get_data
from ftw.saml2auth.utils import create_authn_request
from xml.etree.ElementTree import fromstring

import unittest


class TestAuthnRequest(unittest.TestCase):

    def authnrequest(self,
                     authn_context=[],
                     authn_context_comparison=u'exact',
                     signing_key=u''):
        req = create_authn_request(
            idp_url=u'https://idp.example.org/saml2/idp/sso',
            acs_url=u'https://sp.example.org/saml2/sp/sso',
            issuer_id=u'https://sp.example.org/saml2',
            nameid_format=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            authn_context=authn_context,
            authn_context_comparison=authn_context_comparison,
            signing_key=signing_key,
            )
        return fromstring(req.toxml())

    def test_authnrequest_attributes(self):
        req = self.authnrequest()
        self.assertEqual(u'https://sp.example.org/saml2/sp/sso',
                         req.get('AssertionConsumerServiceURL'))
        self.assertEqual(u'https://idp.example.org/saml2/idp/sso',
                         req.get('Destination'))
        self.assertEqual(u'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                         req.get('ProtocolBinding'))

    def test_authnrequest_issuer(self):
        req = self.authnrequest()
        issuer = req.find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text
        self.assertEqual('https://sp.example.org/saml2',
                         issuer)

    def test_authnrequest_nameidpolicy(self):
        req = self.authnrequest()
        nameid_format = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy').get('Format')
        self.assertEqual(
            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            nameid_format)

    def test_authnrequest_without_authn_context(self):
        req = self.authnrequest()
        authn_context = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext')
        self.assertIsNone(authn_context)

    def test_authnrequest_with_single_authn_context(self):
        req = self.authnrequest(
            authn_context=['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'])
        authn_context = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext').find(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef').text
        self.assertEqual(
            'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            authn_context)

    def test_authnrequest_with_multiple_authn_contexts(self):
        req = self.authnrequest(authn_context=[
            u'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            u'urn:federation:authentication:windows',
        ])
        class_refs = req.find(
            '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext').findall(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef')
        self.assertEqual(
            u'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            class_refs[0].text)
        self.assertEqual(
            u'urn:federation:authentication:windows',
            class_refs[1].text)

    def test_signed_authnrequest_contains_signature(self):
        signing_key = get_data('signing.key').decode('utf8')
        req = self.authnrequest(signing_key=signing_key)
        self.assertIsNotNone(
            req.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))

    def test_unsigned_authnrequest_doesnt_contain_signature(self):
        req = self.authnrequest()
        self.assertIsNone(
            req.find('{http://www.w3.org/2000/09/xmldsig#}Signature'))
