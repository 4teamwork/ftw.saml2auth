from zope.interface import Interface
from zope import schema
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm

authn_context_classes = SimpleVocabulary([
    SimpleTerm(
        value=u'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
        title=u'Password Protected Transport'),
    SimpleTerm(
        value=u'urn:federation:authentication:windows',
        title=u'Integrated Windows Authentication'),
])

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


class IServiceProviderSettings(Interface):

    idp_url = schema.TextLine(
        title=u'IdP URL',
        description=u'URL of the IdP endpoint where AuthnRequests are send to.',
        default=u'',
    )

    issuer_id = schema.TextLine(
        title=u'Issuer ID',
        description=u'Unique identifier of the service provider',
        default=u'',
    )

    authn_context = schema.Choice(
        title=u'NameID Format',
        vocabulary=authn_context_classes,
        default=u'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    )

    nameid_format = schema.Choice(
        title=u'NameID Format',
        vocabulary=nameid_formats,
        default=u'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    )

    sign_authnrequest = schema.Bool(
        title=u'Sign AuthNRequest',
        description=u'Enable signing of AuthNRequests',
        default=False,
    )

    signing_key = schema.Text(
        title=u'Siging Key',
        description=u'',
    )

    signing_cert = schema.Text(
        title=u'Signing Certificate',
        description=u'',
    )


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
        title=u'IdP Encryption Key',
        description=u'',
    )

    idp_encryption_cert = schema.Text(
        title=u'IdP Encryption Certificate',
        description=u'',
    )
