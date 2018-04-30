import dm.xmlsec.binding
dm.xmlsec.binding.initialize()


def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
    from AccessControl.Permissions import manage_users
    from ftw.saml2auth import plugin

    registerMultiPlugin(plugin.SAML2Plugin.meta_type)
    context.registerClass(
        plugin.SAML2Plugin,
        permission=manage_users,
        constructors=(plugin.manage_addSAML2Plugin,
                      plugin.addSAML2Plugin),
        visibility=None)
