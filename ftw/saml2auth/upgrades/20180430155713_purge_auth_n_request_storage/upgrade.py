from ftw.upgrade import UpgradeStep
from zope.annotation.interfaces import IAnnotations
from ftw.saml2auth.storage import ANNOTATION_KEY


class PurgeAuthNRequestStorage(UpgradeStep):
    """Purge authn request storage.
    """

    def __call__(self):
        annotations = IAnnotations(self.portal)
        if ANNOTATION_KEY in annotations:
            del annotations[ANNOTATION_KEY]
