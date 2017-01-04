from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.requestmethod import postonly
from App.class_init import default__class_init__ as InitializeClass
from BTrees.OIBTree import OITreeSet
from OFS.Cache import Cacheable
from Products.CMFCore.permissions import ManagePortal
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.interfaces.plugins import (
    IRolesPlugin,
    IUserEnumerationPlugin
)
from zope.interface import implements
import logging


logger = logging.getLogger('ftw.saml2auth')

manage_addSAML2Plugin = PageTemplateFile(
    "www/addPlugin",
    globals(),
    __name__="manage_addSAML2Plugin",
)


def addSAML2Plugin(self, id_, title='', REQUEST=None):
    """Add a Saml2 Web SSO plugin to a Pluggable Authentication Service.
    """
    p = SAML2Plugin(id_, title)
    self._setObject(p.getId(), p)

    if REQUEST is not None:
        REQUEST["RESPONSE"].redirect(
            "%s/manage_workspace?manage_tabs_message=Saml2+Web+SSO+plugin+"
            "added." % self.absolute_url())


class SAML2Plugin(BasePlugin):
    """SAML2 plugin.
    """
    implements(
        IRolesPlugin,
        IUserEnumerationPlugin
    )

    meta_type = "ftw.saml2auth plugin"
    security = ClassSecurityInfo()

    # ZMI tab for configuration page
    manage_options = (
        ({'label': 'Configuration',
          'action': 'manage_config'},) +
        BasePlugin.manage_options +
        Cacheable.manage_options
    )

    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title
        self._roles = ()
        self._logins = OITreeSet()

    def addUser(self, userid):
        self._logins.insert(userid)

    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
                       sort_by=None, max_results=None, **kw):

        # Only return a user if an id or a login was provided.
        # We need this for updateCredentials of the default session plugin.

        if id and login and id != login:
            return None

        if (id and not exact_match) or kw:
            return None

        key = id and id or login

        if key not in self._logins:
            return None

        return [
            {
                "id": key,
                "login": key,
                "pluginid": self.getId(),
            }
        ]

    # IRolesPlugin
    def getRolesForPrincipal(self, principal, request=None):
        # Return a list of roles for the given principal (a user or group).
        if principal.getId() in self._logins:
            return self._roles

        return ()

    security.declareProtected(ManagePortal, 'manage_updateConfig')

    @postonly
    def manage_updateConfig(self, REQUEST):
        """Update configuration of SAML2 plugin.
        """
        response = REQUEST.response

        roles = REQUEST.form.get('roles')
        self._roles = tuple([role.strip() for role in roles.split(',')])

        response.redirect('%s/manage_config?manage_tabs_message=%s' %
                          (self.absolute_url(), 'Configuration+updated.'))

    def roles(self):
        """Accessor for config form"""
        return ','.join(self._roles)

InitializeClass(SAML2Plugin)
