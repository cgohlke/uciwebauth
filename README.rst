Access UCI WebAuth, LDAP person records, and Active Directory user objects
==========================================================================

:Author:
  `Christoph Gohlke <https://www.lfd.uci.edu/~gohlke/>`_

:Organization:
  Laboratory for Fluorescence Dynamics. University of California, Irvine

:Version: 2018.8.30

Requirements
------------
* `CPython 3.5+ <https://www.python.org>`_
* `Python-ldap 3.1 <https://www.python-ldap.org>`_
* `Pywin32 223 <https://github.com/mhammond/pywin32>`_

Revisions
---------
2018.8.30
    Move uciwebauth.py module into uciwebauth package.
2018.5.25
    Add Active Directory Service Interfaces for user accounts.
    Drop support for Python 2.
    Remove Django backend.
2008.x.x
    Initial release.

References
----------
(1) OIT WebAuth: A tool for validating UCInetIDs on the Web.
    https://www.oit.uci.edu/idm/webauth/
(2) UCI LDAP Directory Service. https://www.oit.uci.edu/idm/ldap/
