from os.path import dirname, join
from ftw.saml2auth import tests


def get_data(filename):
    """Read data from file in data folder and return it's content as string."""
    filename = join(dirname(tests.__file__), 'data', filename)
    return open(filename, 'r').read()
