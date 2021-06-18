Access UCI WebAuth, LDAP person records, and Active Directory user objects
==========================================================================

Uciwebauth is a Python library to access identity management and authentication
services at the University of California, Irvine (UCI):

1. WebAuth provides a secure, single sign-on authentication solution tool
   for web applications.
2. LDAP (Lightweight Directory Access Protocol) provides information from
   the Campus Directory.
3. ADSI (Active Directory Service Interfaces) enables managing user objects
   in a Microsoft AD.

:Author:
  `Christoph Gohlke <https://www.lfd.uci.edu/~gohlke/>`_

:Organization:
  Laboratory for Fluorescence Dynamics. University of California, Irvine

:License: BSD 3-Clause

:Version: 2021.6.18

Requirements
------------
* `CPython >= 3.7 <https://www.python.org>`_
* `Python-ldap 3.3 <https://www.python-ldap.org>`_
* `Pywin32 301 <https://github.com/mhammond/pywin32>`_

Revisions
---------
2021.6.18
    Revert new WebAuth URLs (not working).
2021.6.6
    Fix uciCampusID query format.
    Use new WebAuth URLs.
    Remove support for Python 3.6 (NEP 29).
2020.1.1
    Remove support for Python 3.5.
2019.1.4
    Fix static code analysis.
2018.9.28
    Add option to authenticate with OIT LDAP service.
    Use OIT instead of Campus LDAP service.
2018.8.30
    Move uciwebauth.py module into uciwebauth package.
2018.5.25
    Add Active Directory Service Interfaces for user accounts.
    Remove support for Python 2.
    Remove Django backend.
2008.x.x
    Initial release.

References
----------
1. OIT WebAuth: A tool for validating UCInetIDs on the Web.
   https://www.oit.uci.edu/idm/webauth/
2. UCI LDAP Directory Service. https://www.oit.uci.edu/idm/ldap/
3. Active Directory Service Interfaces.
   https://docs.microsoft.com/en-us/windows/win32/adsi/
