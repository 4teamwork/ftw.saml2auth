from zope.interface import Interface
from zope import schema
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm


nameid_formats = SimpleVocabulary([
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        title=u'Unspecified'),
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        title=u'E-Mail'),
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        title=u'Persistent'),
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        title=u'Transient'),
])


class IIdentityProviderSettings(Interface):

    nameid_property = schema.TextLine(
        title=u'NameID Attribute',
        description=u'The member property used to identify the subject of a '
                     'SAML assertion (e.g. id or email).',
        default=u'id',
    )

    nameid_format = schema.Choice(
        title=u'NameID Format',
        vocabulary=nameid_formats,
        default=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    )

    idp_signing_key = schema.Text(
        title=u'IdP Siging Key',
        description=u'',
    )

    idp_signing_cert = schema.Text(
        title=u'IdP Signing Certificate',
        description=u'',
    )

    idp_encryption_key = schema.Text(
        title=u'IdP Key',
        description=u'',
    )

    idp_cert = schema.Text(
        title=u'IdP Certificate',
        description=u'',
    )