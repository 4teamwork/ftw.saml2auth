Introduction
============

This product provides a PAS plugin for authentication of users in
Plone using the SAML 2.0 Webbrowser SSO profile where Plone will
act as a service provider (SP). It can be used in combination with an
identity provider (IdP) supporting the SAML 2.0 Webbrowser SSO profile
(e.g. Microsoft Active Directory Federation Services 2.0 or 3.0).

Currently only the POST binding is supported.


AD FS 3.0 Setup
---------------

Instructions to setup AD FS 3.0 as an IdP:

- Install AD FS 3.0

- Open AD FS Management

- Add Relying Party Trust

  - Enter data about relying party manually

  - Choose AD FS profile

  - Enable support for the SAML 2.0 WebSSO protocol

  - Enter the URL of your Plone site as service url (must be HTTPS)

  - Add Relying party trust identifier

- Edit Claim Rules

  - Add claim rule: Send LDAP attributes as claims

  - Add claim rule: Transform an incoming claim

Identity Provider Metadata can be downloaded from the url:
https://fs.domain.local/FederationMetadata/2007-06/FederationMetadata.xml


Links
=====

- Main project repository: https://github.com/4teamwork/ftw.saml2auth
- Issue tracker: https://github.com/4teamwork/ftw.saml2auth/issues


Copyright
=========

This package is copyright by `4teamwork <http://www.4teamwork.ch/>`_.

``ftw.saml2auth`` is licensed under GNU General Public License, version 2.