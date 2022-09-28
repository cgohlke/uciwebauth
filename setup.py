# uciwebauth/setup.py

"""Uciwebauth package Setuptools script."""

import sys
import re

from setuptools import setup


def search(pattern, code, flags=0):
    # return first match for pattern in code
    match = re.search(pattern, code, flags)
    if match is None:
        raise ValueError(f'{pattern!r} not found')
    return match.groups()[0]


with open('uciwebauth/uciwebauth.py') as fh:
    code = fh.read()

version = search(r"__version__ = '(.*?)'", code)

description = search(r'"""(.*)\.(?:\r\n|\r|\n)', code)

readme = search(
    r'(?:\r\n|\r|\n){2}"""(.*)"""(?:\r\n|\r|\n){2}[__version__|from]',
    code,
    re.MULTILINE | re.DOTALL,
)

readme = '\n'.join(
    [description, '=' * len(description)] + readme.splitlines()[1:]
)

license = search(
    r'(# Copyright.*?(?:\r\n|\r|\n))(?:\r\n|\r|\n)+""',
    code,
    re.MULTILINE | re.DOTALL,
)

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
    author_email='cgohlke@cgohlke.com',
    url='https://www.cgohlke.com',
    project_urls={
        'Bug Tracker': 'https://github.com/cgohlke/uciwebauth/issues',
        'Source Code': 'https://github.com/cgohlke/uciwebauth',
        # 'Documentation': 'https://',
    },
    packages=['uciwebauth'],
    python_requires='>=3.7',
    install_requires=[],
    extras_require={
        'ldap': ['python-ldap>=3.3'],
        'adsi': [
            'pywin32>=300; sys_platform == "win32"'
            ' and platform_python_implementation != "PyPy"'
        ],
        'all': [
            'python-ldap>=3.3',
            'pywin32>=300; sys_platform == "win32"'
            ' and platform_python_implementation != "PyPy"',
        ],
    },
    license='BSD',
    platforms=['any'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
