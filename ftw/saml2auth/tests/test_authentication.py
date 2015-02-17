from Products.CMFCore.utils import getToolByName
from ftw.saml2auth.testing import FTW_SAML2AUTH_INTEGRATION_TESTING
import unittest


class TestSaml2WebSSOAuthentication(unittest.TestCase):

    layer = FTW_SAML2AUTH_INTEGRATION_TESTING

    def setUp(self):
        self.portal = self.layer['portal']
        self.plugin = self.portal.acl_users['saml2_websso']
        self.userid = 'jim@domain.local'
        self.plugin._logins.insert(self.userid)

    def test_dont_authenticate_credentials_from_other_extractors(self):
        creds = {'subject': self.userid, 'extractor': 'other'}
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))

    def test_authenticate_credentials_from_our_extractor(self):
        creds = {
            'subject': self.userid,
            'extractor': self.plugin.getId()
        }
        self.assertEqual(
            (self.userid, self.userid),
            self.plugin.authenticateCredentials(creds))

    def test_dont_authenticate_credentials_without_subject(self):
        creds = {
            'login': self.userid,
            'extractor': self.plugin.getId()
        }
        self.assertEqual(None, self.plugin.authenticateCredentials(creds))

    def test_set_member_properties(self):
        creds = {
            'subject': self.userid,
            'extractor': self.plugin.getId(),
            'attributes': {
                'fullname': 'Jim Raynor',
                'email': 'jim.raynor@domain.local',
            },
        }
        self.assertEqual(
            (self.userid, self.userid),
            self.plugin.authenticateCredentials(creds))
        mtool = getToolByName(self.portal, 'portal_membership')
        member = mtool.getMemberById(self.userid)
        self.assertEqual('Jim Raynor', member.getProperty('fullname'))
        self.assertEqual('jim.raynor@domain.local',
                         member.getProperty('email'))
