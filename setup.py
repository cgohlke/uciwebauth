# uciwebauth/setup.py

"""Uciwebauth package setuptools script."""

import sys
import re

from setuptools import setup

with open('uciwebauth/uciwebauth.py') as fh:
    code = fh.read()

version = re.search(r"__version__ = '(.*?)'", code).groups()[0]

description = re.search(r'"""(.*)\.(?:\r\n|\r|\n)', code).groups()[0]

readme = re.search(r'(?:\r\n|\r|\n){2}"""(.*)"""(?:\r\n|\r|\n){2}__version__',
                   code, re.MULTILINE | re.DOTALL).groups()[0]

readme = '\n'.join([description, '=' * len(description)] +
                   readme.splitlines()[1:])

license = re.search(r'(# Copyright.*?(?:\r\n|\r|\n))(?:\r\n|\r|\n)+""', code,
                    re.MULTILINE | re.DOTALL).groups()[0]

license = license.replace('# ', '').replace('#', '')

if 'sdist' in sys.argv:
    with open('LICENSE', 'w') as fh:
        fh.write('BSD 3-Clause License\n\n')
        fh.write(license)
    with open('README.rst', 'w') as fh:
        fh.write(readme)

setup(
    name='uciwebauth',
    version=version,
    description=description,
    long_description=readme,
    author='Christoph Gohlke',
    author_email='cgohlke@uci.edu',
    url='https://www.lfd.uci.edu/~gohlke/',
    packages=['uciwebauth'],
    python_requires='>=3.6',
    install_requires=[],
    extras_require={
        'ldap': ['python-ldap>=3.1'],
        'adsi': ['pywin32>=226;platform_system=="Windows"'],
        'all': ['python-ldap>=3.1', 'pywin32>=226;platform_system=="Windows"'],
    },
    license='BSD',
    platforms=['any'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
