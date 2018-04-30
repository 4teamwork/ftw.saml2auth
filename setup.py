from setuptools import setup, find_packages
import os

version = '1.0'

tests_require = [
    'plone.app.testing',
    'freezegun',
]

setup(name='ftw.saml2auth',
      version=version,
      description="SAML 2.0 Web SSO authentication for Plone",
      long_description=open("README.rst").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      # Get more strings from
      # http://pypi.python.org/pypi?:action=list_classifiers
      classifiers=[
          "Framework :: Plone",
          "Programming Language :: Python",
      ],
      keywords='',
      author='4teamwork AG',
      author_email='info@4teamwork.ch',
      url='https://github.com/4teamwork/ftw.saml2auth',
      license='GPL',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['ftw'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'Plone',
          'plone.api',
          'ftw.upgrade',
          'setuptools',
          'netaddr',
          'python-saml',
      ],
      tests_require=tests_require,
      extras_require={
          'tests': tests_require,
      },
      entry_points="""
      # -*- Entry points: -*-

      [z3c.autoinclude.plugin]
      target = plone
      """,
      )
