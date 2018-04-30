from BTrees.OOBTree import OOBTree
from ftw.saml2auth.interfaces import IAuthNRequestStorage
from zope.annotation.interfaces import IAnnotations
from zope.interface import implements
import time

ANNOTATION_KEY = 'ftw.saml2auth.requests'


class AuthNRequestStorage(object):
    implements(IAuthNRequestStorage)

    def __init__(self, context):
        self.context = context
        annotations = IAnnotations(context)
        self._id_to_url = annotations.setdefault(ANNOTATION_KEY, OOBTree())

    def add(self, id_, url):
        """Store the given id and url."""
        self._id_to_url[id_] = (url, int(time.time()))

    def pop(self, id_):
        """Remove the given id and return the associated url."""
        if id_ in self._id_to_url:
            url = self._id_to_url[id_][0]
            del self._id_to_url[id_]
            return url
        return None

    def cleanup(self):
        """Remove old entries."""
        now = int(time.time())
        for k in list(self._id_to_url.keys()):
            if now > self._id_to_url[k][1] + 120:
                del self._id_to_url[k]
