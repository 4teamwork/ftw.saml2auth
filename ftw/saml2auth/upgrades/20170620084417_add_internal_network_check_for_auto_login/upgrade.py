from ftw.upgrade import UpgradeStep


class AddInternalNetworkCheckForAutoLogin(UpgradeStep):
    """Add internal network check for auto login.
    """

    def __call__(self):
        self.install_upgrade_profile()
