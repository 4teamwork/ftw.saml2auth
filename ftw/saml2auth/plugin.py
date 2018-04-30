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
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.utils import csrf_only
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
          'action': 'manage_config'},
          {'label': 'Users',
          'action': 'manage_users'},) +
        BasePlugin.manage_options +
        Cacheable.manage_options
    )

    security.declareProtected(ManagePortal, 'manage_config')
    manage_config = PageTemplateFile('www/config', globals(),
                                     __name__='manage_config')

    security.declareProtected(ManageUsers, 'manage_users')
    manage_users = PageTemplateFile('www/manage_users', globals(),
                                    __name__='manage_users')

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title
        self._roles = ()
        self._logins = OITreeSet()

    def addUser(self, userid):
        if userid in self._logins:
            return

        self._logins.insert(userid)

    def removeUser(self, userid):
        if userid not in self._logins:
            return

        self._logins.remove(userid)

    def listUserInfo(self):
        """ -> ( {}, ...{} )

        o Return one mapping per user, with the following keys:

          - 'user_id'
          - 'login_name'
        """
        return [{'user_id': x, 'login_name': x} for x in self._logins]

    security.declareProtected( ManageUsers, 'manage_addUser')

    @csrf_only
    @postonly
    def manage_addUser(self, user_id,
                       RESPONSE=None,
                       REQUEST=None):
        """ Add a user via the ZMI.
        """
        self.addUser(user_id)

        message = 'User+added'

        if RESPONSE is not None:
            RESPONSE.redirect('{}/manage_users?manage_tabs_message={}'.format(
                self.absolute_url(), message))

    security.declareProtected(ManageUsers, 'manage_removeUsers')

    @csrf_only
    @postonly
    def manage_removeUsers(self, user_ids,
                       RESPONSE=None,
                       REQUEST=None):
        """ Remove one or more users via the ZMI.
        """
        user_ids = filter(None, user_ids)

        if not user_ids:
            message = 'no+users+selected'

        else:
            for user_id in user_ids:
                self.removeUser( user_id )

            message = 'Users+removed'

        if RESPONSE is not None:
            RESPONSE.redirect('{}/manage_users?manage_tabs_message={}'.format(
                self.absolute_url(), message))


    # IUserEnumerationPlugin implementation
    def enumerateUsers(self, id=None, login=None, exact_match=False,
                       sort_by=None, max_results=None, **kw):

        key = id and id or login
        user_infos = []
        pluginid = self.getId()

        # We do not provide search for additional keywords
        if kw:
            return ()

        if not key:
            # Return all users
            for login in self._logins:
                user_infos.append({
                    "id": login,
                    "login": login,
                    "pluginid": pluginid,
                    })
        elif key in self._logins:
            # User does exists
            user_infos.append({
                "id": key,
                "login": key,
                "pluginid": pluginid,
                })
        else:
            # User does not exists
            return ()

        if max_results is not None and max_results >= 0:
            user_infos = user_infos[:max_results]

        return tuple(user_infos)

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
