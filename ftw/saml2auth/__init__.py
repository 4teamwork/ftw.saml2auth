import dm.xmlsec.binding
dm.xmlsec.binding.initialize()


def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
    from AccessControl.Permissions import manage_users
    from ftw.saml2auth import plugin

    registerMultiPlugin(plugin.Saml2WebSSOPlugin.meta_type)
    context.registerClass(
        plugin.Saml2WebSSOPlugin,
        permission=manage_users,
        constructors=(plugin.manage_addSaml2WebSSOPlugin,
                      plugin.addSaml2WebSSOPlugin),
        visibility=None)
