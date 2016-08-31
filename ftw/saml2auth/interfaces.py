from zope.interface import Interface
from zope import schema
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm


nameid_formats = SimpleVocabulary([
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        title=u'E-Mail'),
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        title=u'Transient'),
])


class IIdentityProviderSettings(Interface):

    nameid_property = schema.TextLine(
        title=u'NameID Attribute',
    )

    nameid_format = schema.Choice(
        title=u'NameID Format',
        vocabulary=nameid_formats,
        value_type=schema.TextLine(),
    )
