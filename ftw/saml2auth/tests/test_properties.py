from ftw.saml2auth.tests import IntegrationTestCase


class TestSaml2FormProperties(IntegrationTestCase):

    def test_view_returns_a_dict_with_all_necessary_parameters(self):
        view = self.portal.restrictedTraverse('@@saml2_form_properties')
        required_keys = ['enabled', 'action', 'authn_request', 'relay_state']

        self.assertItemsEqual(required_keys, view().keys())
