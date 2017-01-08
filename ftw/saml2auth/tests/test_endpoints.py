from AccessControl import Unauthorized
from ftw.saml2auth.browser.saml2 import Saml2View
from ftw.saml2auth.errors import SAMLResponseError
from ftw.saml2auth.interfaces import IServiceProviderSettings
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
from ftw.saml2auth.tests.utils import get_data
from ftw.saml2auth.utils import create_saml_response
from plone.app.testing import logout
from plone.registry.interfaces import IRegistry
from zExceptions import BadRequest
from zope.component import queryUtility
from ftw.saml2auth.interfaces import IAuthNRequestStorage
import base64
import unittest


class TestExtractAuthnRequest(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']

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

    def test_anonymous_without_authnrequest_raises_badrequest(self):
        logout()
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        with self.assertRaises(BadRequest):
            req, rs = s2view.extract_authn_request()

    def test_anonymous_sets_cookie_and_raises_unauthorized(self):
        logout()
        doc = get_data('authnrequest.xml').decode('utf8')
        self.layer['request'].form.update({
            'SAMLRequest': base64.b64encode(doc),
        })
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        with self.assertRaises(Unauthorized):
            req, rs = s2view.extract_authn_request()
        self.assertIn('_ftwsaml2auth', self.layer['request'].response.cookies)
        self.assertEqual(
            '/',
            self.layer['request'].response.cookies['_ftwsaml2auth']['path'])

    def test_authenticated_extract_from_cookie(self):
        self.request.cookies.update({
            '_ftwsaml2auth': 'eJx9UsGO0zAUPLNfEfnALXHsZtPWarIqrRCVFojawIELMo67'
            'tZTYxs9Zyt/jZFNRBPRk6Wlm3rzxrB7OXRs9SwfK6AKRJEXRQ3m3At61lq17f9J7+'
            'b2X4KM1gHQ+wDZGQ99Jd5DuWQn5af9YoJP3lmGszcmAx7Y1WuJBg2KwGMCgaBs0lO'
            'Z+3DPAIeBVYxN55p1tZWLc00QJ0xfOblugr7lIm4ZIHqfZ/D7OlpzHy/mRx4QuFjR'
            'bZnlOaYAC9HKnwXPtC0RTkseExDSvCWXpnN3PEjLL8sXsC4oqZ7wRpn2jdKP0U4F6'
            'p5nhoIBp3klgXrDD+v0jo0nKvr2AgL2r6yquPh5qFH2+xEWHuEKAGtjg/LYSv+R3T'
            'bG3OXayisq7V+OfsPFOV14ChD/zW+Fr0MSx7EMQ3m0r0yrxM3prXMf9//eShIwT1c'
            'THEcpkx1W7bhonARD+LTs1QzZjT0ItvDz7aGM6y52CIaDgTfjB/OT+GrhpQyJ7eSx'
            'vhiaYGHBhXIXnh3HN8H1ShK214xqscX66+p/iwSy+4TZUHf/d9fL1LwDTENE='})
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        req, rs = s2view.extract_authn_request()
        self.assertEqual('_6c0dd1ea-0475-49aa-97fa-128824946622', req.ID)
        self.assertEqual('', rs)

    def test_authenticated_extract_from_cookie_with_relaystate(self):
        self.request.cookies.update({
            '_ftwsaml2auth': 'eJx9Uk2P0zAUPLO/IvKBWz7sZtPWarIqrRCVFjZqAwcuyCSv'
            'W4vENn7ubvn3ONlUWwT0ZOlpZt688SzuTl0bPIFFqVVOaJSQ4K64WaDoWsOXR3dQW'
            '/h5BHTBEhGs87CVVnjswO7APskaPm/vc3JwzvA4Vvqg0cWm1QriXoPFaGJETYK115'
            'BKuGFPD0ePl42J4CQ600Kk7eNI8dMXzmadk29ZnTQNBREm6fQ2TOdChPPpXoSUzWY'
            'snadZxpiHIh5ho9AJ5XLCEpqFlIYsqyjjyZTfTiI6SbPZ5CsJSqudrnX7TqpGqsec'
            'HK3iWqBErkQHyF3Nd8uP95xFCf/+AkL+oarKsHzYVST4co6L9XH5ABXy3vl1JXHO7'
            '5JirnPMaJUUN2+GP+HDnbY4B4h/5reIL0Ejx/BPXnizLnUr61/Be2074f6/l0Z0mM'
            'gm3A9QDp2Q7bJpLCCS+FV2bAY0Q098LRycXLDSnRFWYh+Q91a73vzo/hK4an0iW9g'
            'XV0Ored3j/Lj0z7O2Tf99UPutlRUKjbZuvPqf4t5sfMWtr3r8d9eLt07/APUbW2ES'
            '8g=='})
        s2view = Saml2View(self.layer['portal'], self.layer['request'])
        req, rs = s2view.extract_authn_request()
        self.assertEqual('_6c0dd1ea-0475-49aa-97fa-128824946622', req.ID)
        self.assertEqual('token', rs)


class TestProcessSAMLResponse(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.request = self.layer['request']
        registry = queryUtility(IRegistry)
        self.settings = registry.forInterface(IServiceProviderSettings)
        self.settings.idp_cert = get_data('signing.crt').decode('utf8')
        self.settings.idp_issuer_id = u'https://idp.example.com'

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
        self.assertEqual('Undecodable SAMLResponse', cm.exception.message)

    def test_invalid_saml_response_raises(self):
        self.request.form.update({
            'SAMLResponse': base64.b64encode('<response>invalid</response>')})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Invalid SAMLResponse', cm.exception.message)

    def test_saml_response_without_signature_raises(self):
        issued_requests = IAuthNRequestStorage(self.portal)
        issued_requests.add(u'_12345', u'https://test')
        resp = create_saml_response(
            in_response_to=u'_12345',
            destination=u'{}/saml2/sp/sso'.format(self.portal.absolute_url()),
            issuer_id=u'https://idp.example.com',
            subject=u'john',
            subject_format=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            audience=u'https://sp.example.com',
        )
        self.request.form.update({
            'SAMLResponse': base64.b64encode(resp)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Unsigned Assertion', cm.exception.message)

    def test_invalid_signature_raises(self):
        resp = create_saml_response(
            in_response_to=u'_12345',
            destination=u'{}/saml2/sp/sso'.format(self.portal.absolute_url()),
            issuer_id=u'https://idp.example.com',
            subject=u'john',
            subject_format=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            audience=u'https://sp.example.com',
            key=get_data('signing.key'),
        )
        resp = resp.replace(u'john', u'admin')
        self.request.form.update({
            'SAMLResponse': base64.b64encode(resp)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Invalid Signature', cm.exception.message)

    def test_unknown_in_repsonse_to_raises(self):
        resp = create_saml_response(
            in_response_to=u'_12345',
            destination=u'{}/saml2/sp/sso'.format(self.portal.absolute_url()),
            issuer_id=u'https://idp.example.com',
            subject=u'john',
            subject_format=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            audience=u'https://sp.example.com',
            key=get_data('signing.key'),
        )
        self.request.form.update({
            'SAMLResponse': base64.b64encode(resp)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Unknown SAMLResponse', cm.exception.message)

    def test_wrong_destination_raises(self):
        issued_requests = IAuthNRequestStorage(self.portal)
        issued_requests.add(u'_12345', u'https://test')
        resp = create_saml_response(
            in_response_to=u'_12345',
            destination=u'http://wrong.net',
            issuer_id=u'https://idp.example.com',
            subject=u'john',
            subject_format=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            audience=u'https://sp.example.com',
            key=get_data('signing.key'),
        )
        self.request.form.update({
            'SAMLResponse': base64.b64encode(resp)})
        s2view = Saml2View(self.portal, self.request)
        with self.assertRaises(SAMLResponseError) as cm:
            s2view.process_saml_response()
        self.assertEqual('Wrong destination', cm.exception.message)
