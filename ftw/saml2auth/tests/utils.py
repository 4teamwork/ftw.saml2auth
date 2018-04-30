from os.path import dirname, join


def get_data(filename):
    """Read data from file in data folder and return it's content as string."""
    filename = join(dirname(__file__), 'data', filename)
    return open(filename, 'r').read()
