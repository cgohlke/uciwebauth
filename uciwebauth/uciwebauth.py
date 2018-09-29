# -*- coding: utf-8 -*-
# uciwebauth.py

# Copyright (c) 2008-2018, Christoph Gohlke
# Copyright (c) 2008-2018, The Regents of the University of California
# Produced at the Laboratory for Fluorescence Dynamics
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# * Neither the name of the copyright holders nor the names of any
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Access UCI WebAuth, LDAP person records, and Active Directory user objects.

Uciwebauth is a library to access identity management and authentication
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

:Version: 2018.9.28

Requirements
------------
* `CPython 3.5+ <https://www.python.org>`_
* `Python-ldap 3.1 <https://www.python-ldap.org>`_
* `Pywin32 224 <https://github.com/mhammond/pywin32>`_

Revisions
---------
2018.9.28
    Add option to authenticate with OIT LDAP service.
    Use OIT instead of Campus LDAP service.
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
1. OIT WebAuth: A tool for validating UCInetIDs on the Web.
   https://www.oit.uci.edu/idm/webauth/
2. UCI LDAP Directory Service. https://www.oit.uci.edu/idm/ldap/
3. Active Directory Service Interfaces.
   https://docs.microsoft.com/en-us/windows/desktop/adsi/

"""

from __future__ import division, print_function

__version__ = '2018.9.28'
__docformat__ = 'restructuredtext en'
__all__ = ('WebAuth', 'WebAuthError', 'LdapPerson', 'LdapPersonError',
           'AdsiUser', 'AdsiUserError', 'WebAuthBackend')


import sys
import os
import re
from html import escape
from urllib.parse import urlencode, urlunsplit
from urllib.request import Request, urlopen


class WebAuth():
    """Authenticate against UCI WebAuth service.

    Raise WebAuthError if authentication fails.

    Attributes
    ----------
    ucinetid_auth: str or None
        64 character string stored in UCI WebAuth database as key to
        other information about login.
    ucinetid : str or None
        UCInetID authenticated with key.
    auth_host : str or None
        IP number of host that key was authenticated from.
    time_created : int or None
        Seconds since epoch that key was authenticated.
    last_checked : int or None
        Seconds since epoch to when webauth_check was last run on key.
    max_idle_time : int or None
    login_timeout : str or None
    campus_id : int or None
        Unique number for every person on UCI campus that will never be
        duplicated or repeated.
    uci_affiliations : str or None
        List of affiliations that a user has with UCI.
        student | staff | employee | guest | alumni | former_student
    age_in_seconds : int or None
        Number of seconds passed since password was authenticated.
    seconds_since_checked : int or None
        Seconds since last time webauth_check was run on key.
    auth_fail : str or None
        Reason for authorization failure.
    error_code : str or None
        Key to ERROR_CODES.

    Examples
    --------
    >>> try:
    ...     auth = WebAuth(TEST_USER, TEST_PASSWORD)
    ... except WebAuthError as e:
    ...     print(e)
    ... else:
    ...     auth.ucinetid == TEST_USER
    ...     try:
    ...         auth.check()
    ...     except WebAuthError as e:
    ...         print(e)
    ...     try:
    ...         auth.logout()
    ...     except WebAuthError as e:
    ...         print(e)
    True

    >>> auth = WebAuth()
    >>> try:
    ...     auth.authenticate('not a valid ucinetid_auth token')
    ... except WebAuthError as e:
    ...     print(e)
    No valid ucinetid_auth token found

    """
    LOGIN_URL = 'https://login.uci.edu/ucinetid/webauth'
    CHECK_URL = 'https://login.uci.edu/ucinetid/webauth_check'
    LOGOUT_URL = 'https://login.uci.edu/ucinetid/webauth_logout'

    USER_AGENT = {'User-Agent': 'Python-urllib/%s uciwebauth.py' %
                  sys.version.split(' ', 1)[0]}

    ERROR_CODES = {
        'WEBAUTH_DOWN': 'The WebAuth Server is currently down',
        'NO_AUTH_KEY': 'No ucinetid_auth was provided',
        'NOT_FOUND': 'The ucinetid_auth is not in the database',
        'NO_AFFILIATION': 'Access denied to see user information'}

    ATTRS = {
        'ucinetid': str, 'auth_host': str, 'time_created': int,
        'last_checked': int, 'max_idle_time': int, 'login_timeout': int,
        'campus_id': str, 'uci_affiliations': str, 'age_in_seconds': int,
        'seconds_since_checked': int, 'auth_fail': str, 'error_code': str}

    def __init__(self, usrid=None, password=None):
        if usrid:
            self.authenticate(usrid, password)
        else:
            self._clear()

    def authenticate(self, usrid, password=None):
        """Get ucinetid_auth token.

        Usrid can be a UCInetId, a 64 byte WebAuth token or any string
        containing the token, e.g. HTTP QUERY_STRING or HTTP_COOKIE.

        Raise WebAuthError on failure.

        """
        self._clear()
        if password is None and len(usrid) > 8:
            self.ucinetid_auth = self._search_token(usrid)
        else:
            self.ucinetid_auth = self._new_token(usrid, password)
        if not self.ucinetid_auth:
            raise WebAuthError('No valid ucinetid_auth token found')
        self.check()

    def check(self):
        """Get data associated with ucinetid_auth token.

        Raise WebAuthError on failure.

        """
        if not self.ucinetid_auth:
            return
        data = urlencode({'ucinetid_auth': self.ucinetid_auth}).encode('utf-8')
        request = Request(self.CHECK_URL, data, self.USER_AGENT)
        try:
            response = urlopen(request).read()
        except Exception as e:
            raise WebAuthError('UCI webauth_check site not found %s' % str(e))
        for line in response.splitlines():
            line = line.decode('utf8')
            try:
                attr, value = line.strip().split('=')
                setattr(self, attr, self.ATTRS[attr](value))
            except (KeyError, ValueError):
                pass
        if self.auth_fail:
            raise WebAuthError(self.auth_fail)

    def logout(self):
        """Clear ucinetid_auth entry in UCI WebAuth database."""
        if not self.ucinetid_auth:
            return
        data = urlencode({'ucinetid_auth': self.ucinetid_auth}).encode('utf-8')
        request = Request(self.LOGOUT_URL, data, self.USER_AGENT)
        try:
            urlopen(request).read()
        except Exception:
            raise WebAuthError('UCI webauth_logout site not found')
        self._clear()

    def validate(self, timeout=None, auth_host=None):
        """Raise WebAuthError if no token, timeout, or host mismatch."""
        if not self.ucinetid_auth or len(self.ucinetid_auth) != 64:
            raise WebAuthError('Not logged in')
        if timeout is not None and self.age_in_seconds > timeout:
            raise WebAuthError('Authentication expired')
        if auth_host and self.auth_host != auth_host:
            raise WebAuthError(
                'Host mismatch: %s != %s' % (self.auth_host, auth_host))

    def login_url(self, return_url=''):
        """Return URL to log in to WebAuth."""
        return self.LOGIN_URL + '?' + urlencode(
            {'return_url': return_url}).replace('&', '&amp;')

    def logout_url(self, return_url=''):
        """Return URL to log out of WebAuth."""
        return self.LOGOUT_URL + '?' + urlencode(
            {'ucinetid_auth': self.ucinetid_auth, 'return_url': return_url}
            ).replace('&', '&amp;')

    def _clear(self):
        """Initialize attributes to None."""
        self.ucinetid_auth = None
        for attr in self.ATTRS:
            setattr(self, attr, None)

    def _search_token(self, search_string):
        """Return ucinetid_auth token from string."""
        if search_string and len(search_string) >= 64:
            pattern = 'ucinetid_auth=' if len(search_string) > 64 else ''
            pattern += '([a-zA-Z0-9_]{64})'
            try:
                return re.search(pattern, search_string).group(1)
            except AttributeError:
                pass
        return None

    def _new_token(self, ucinetid, password):
        """Authenticate username/password and get new ucinetid_auth token."""
        if password is None or not ucinetid or len(ucinetid) > 8:
            raise WebAuthError('Invalid ucinetid or password')
        data = urlencode({'ucinetid': ucinetid, 'password': password,
                          'return_url': '', 'referer': '', 'info_text': '',
                          'info_url': '', 'submit_type': '',
                          'login_button': 'Login'}).encode('utf-8')
        request = Request(self.LOGIN_URL, data, self.USER_AGENT)
        try:
            response = urlopen(request)
        except Exception:
            raise WebAuthError('UCI webauth site not found')
        try:
            cookie = response.info()['Set-Cookie']
            if 'ucinetid_auth' not in cookie:
                raise ValueError()
        except Exception:
            raise WebAuthError('Cookie not found')
        ucinetid_auth = self._search_token(cookie)
        if not ucinetid_auth:
            raise WebAuthError('Authentication failed')

        return ucinetid_auth

    def __str__(self):
        """Return string with information about authenticated UCInetId."""
        output = ['ucinetid_auth=%s' % self.ucinetid_auth]
        for attr in self.ATTRS:
            value = getattr(self, attr)
            if value is not None:
                output.append('%s=%s' % (attr, value))
        return '\n'.join(output)


class WebAuthError(Exception):
    """Base class for errors in the WebAuth class."""
    pass


class LdapPerson():
    """A person entry in the UCI LDAP directory.

    Raise LdapPersonError if search fails or results are ambiguous
    or not a person.

    The first item of any LDAP record field listed in ATTRS is stored
    as an attribute.
    The complete LDAP search results are stored as 'records' attribute.

    Examples
    --------
    >>> try:
    ...     p = LdapPerson(TEST_USER)
    ... except LdapPersonError:
    ...     print('LdapPerson failed')
    ... else:
    ...     p2 = LdapPerson(p.uciCampusID)
    ...     p3 = LdapPerson('*%s %s*' % (p.givenName, p.middleName), 'cn')
    ...     (p.cn == p2.cn) and (p.mail == p3.mail)
    True

    """
    SERVER = 'ldaps://ldap.oit.uci.edu:636'  # 'ldap://ldap.oit.uci.edu:389'
    BASEDN = 'ou=people,dc=uci,dc=edu'
    TYPES = b'uciPerson', b'eduPerson', b'PERSON', b'STUDENT'
    ATTRS = (
        'appointmentType', 'cn', 'createTimestamp', 'dn', 'department',
        'departmentNumber', 'displayName', 'eduPersonAffiliation',
        'eduPersonPrincipalName', 'eduPersonPrincipalNamePrior',
        'eduPersonOrgDN', 'eduPersonScopedAffiliation', 'employeeNumber',
        'facsimileTelephoneNumber', 'givenName', 'l', 'mail', 'major',
        'memberOf', 'middleName', 'modifyTimestamp', 'myDotName', 'o',
        'objectClass', 'ou', 'postalAddress', 'postalCode', 'sn', 'st',
        'telephoneNumber', 'title', 'uciAdminAppCSS', 'uciAffiliation',
        'uciApplicantEmail', 'uciCampusID', 'uciCTOCode', 'uciEmployeeClass',
        'uciEmployeeClassDescription', 'uciEmployeeGivenName',
        'uciEmployeeMiddleName', 'uciEmployeeSN', 'uciEmployeeStatus',
        'uciEmployeeStatusCode', 'uciFloater', 'uciGuestExpiration',
        'uciHomeDepartment', 'uciHomeDepartmentCode',
        'uciHomeDepartmentCodeTitle', 'uciHrStatus', 'uciKFSCampusCode',
        'uciKFSChart', 'uciKFSChartOrgCode', 'uciKFSChartOrgName',
        'uciKFSOrgCode', 'uciMailDeliveryPoint', 'ucinetidLocked',
        'ucinetidLockedAt', 'ucinetidPasswordChangeAt', 'ucinetidReset',
        'ucinetidResetAt', 'uciPrimaryCTOCode', 'uciPrimaryEmployeeClass',
        'uciPrimaryEmployeeClassDescription', 'uciPrimaryTitle',
        'uciPrimaryTitleCode', 'uciPublishFlag', 'uciRecentlyHired',
        'uciReleaseFlag', 'uciSNAPTemplate', 'uciSponsorDepartment',
        'uciSponsorDepartmentCode', 'uciSponsorID', 'uciStudentEmailRelease',
        'uciStudentGivenName', 'uciStudentID', 'uciStudentLevel',
        'uciStudentMiddleName', 'uciStudentSN', 'uciSupervisorDN',
        'uciSupervisorRoleFlag', 'uciTestAccount', 'uciUCNetID', 'uciVPNFlag',
        'uciWebMailAddress', 'uciZotCode', 'uciZotCodeName', 'uid')

    def __init__(self, query, rdn=None, uid=None, pwd=None, verifyssl=False,
                 server=SERVER, basedn=BASEDN, attributes=ATTRS, types=TYPES):
        """Search LDAP directory for query and set attributes from results.

        Query is searched in 'uid' (if string), 'uciCampusID' (if int),
        or the relative distinguished name 'rdn' if specified.

        Raise LdapPersonError on failure.

        """
        import ldap  # noqa: delayed import

        if not verifyssl:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        if not query:
            raise ValueError('empty query')
        if query[0] == '(' and query[-1] == ')':
            pass
        elif rdn:
            query = '(%s=%s)' % (rdn, query)
        else:
            try:
                query = '(uciCampusID=%.12i)' % int(query)
            except Exception:
                query = '(uid=%s)' % query

        if uid and pwd and server == self.SERVER:
            server = server.replace('ldap.', 'ldap-auth.')

        try:
            ldapobj = ldap.initialize(server)
        except ldap.LDAPError as e:
            raise LdapPersonError(e)

        if uid and pwd:
            ldapobj.simple_bind_s('uid=%s,%s' % (uid, basedn), pwd)

        try:
            id_ = ldapobj.search(basedn, ldap.SCOPE_SUBTREE, query, None)
            results = []
            while 1:
                ltype, data = ldapobj.result(id_, 0)
                if not data:
                    break
                elif ltype == ldap.RES_SEARCH_ENTRY:
                    results.append(data)
        except ldap.LDAPError as e:
            raise LdapPersonError(e)

        if len(results) != 1:
            raise LdapPersonError('%s not found or result ambiguous.' % query)

        self.dn, self.records = results[0][0]
        if not self._is_type(types):
            raise LdapPersonError('%s has wrong type.' % query)

        for attr in attributes:
            if attr in self.records:
                value = self.records[attr][0].decode('utf8')
                setattr(self, attr, value)
            else:
                setattr(self, attr, None)

        try:
            self.pretty_name = ' '.join((self.givenName.split()[0].title(),
                                         self.sn.title()))
        except Exception:
            self.pretty_name = None

    def _is_type(self, types):
        """Return whether record is one of types."""
        if not types:
            return True
        for type_ in ('objectClass', 'type'):
            if type_ in self.records:
                for value in self.records[type_]:
                    if value in types:
                        return True
        return False

    def __str__(self):
        """Return string with information about person."""
        return '\n'.join('%s=%s' % (attr, getattr(self, attr))
                         for attr in self.ATTRS if getattr(self, attr))


class LdapPersonError(Exception):
    """Base class for errors in the LdapPerson class."""
    pass


class AdsiUser():
    """Active Directory Service Interfaces User Account.

    Examples
    --------
    >>> user = AdsiUser('userid', username='username', password='password',
    ...     dnname='LDAP://myserver/ou=Users,ou=myou,dc=mydomain,dc=com')
    >>> user.enable()
    >>> user.unlock()
    >>> user.set_password('new-password')

    """
    def __init__(self, userid, dnname, username, password):
        """Initialize ADSI user object from userid.

        Raise AdsiUserError if userid is not found.

        Parameters
        ----------
        userid : str
            The Active Directory Id of a user.
        dnname : str
            The ADsPath to the ADSI user object.
        username : str
            The user name to be used for securing permission from the
            namespace server.
        password: str
            The password to be used to obtain permission from the
            namespace server.

        """
        import win32com  # noqa: delayed import
        import win32com.adsi  # noqa: delayed import
        self.user = ''
        adsi = win32com.client.Dispatch('ADsNameSpaces')
        ldap = adsi.getobject('', 'LDAP:')

        users = ldap.OpenDSObject(dnname, username, password, 1)
        for user in users:
            if user.Class == 'user' and user.samAccountName == userid:
                self.user = user
        if self.user == '':
            raise AdsiUserError('user not found')

    def enable(self):
        """Enable user account. Return True if account has been enabled."""
        if self.user.AccountDisabled:
            self.user.AccountDisabled = False
            self.user.SetInfo()
            return True

    def unlock(self):
        """Unlock user account. Return True if account has been unlocked."""
        if self.user.IsAccountLocked:
            self.user.IsAccountLocked = False
            self.user.SetInfo()
            return True

    def set_password(self, password, validate=None):
        """Set user account password."""
        if validate:
            validate(password)
        self.user.setpassword(password)
        # disable "Must change password at next logon"
        self.user.Put('pwdLastSet', -1)
        self.user.SetInfo()

    @property
    def must_change_password(self):
        """Return if user must change password at next logon."""
        return (self.user.pwdLastSet.lowpart +
                self.user.pwdLastSet.highpart == 0)

    @property
    def is_disabled(self):
        """Return if user account is disabled."""
        return self.user.AccountDisabled

    def __str__(self):
        """Return string with information about user."""
        return '\n'.join('%s: %s' % (key, getattr(self.user, key)) for key in (
            'cn', 'samAccountName', 'Fullname', 'Description',
            'PasswordMinimumLength', 'AccountExpirationDate',
            'AccountDisabled'))


class AdsiUserError(Exception):
    """Base class for errors in the AdsiUser class."""
    pass


class WebAuthBackend():
    """UCI WebAuth backend for use in web apps.

    Attributes
    ----------
    auth : WebAuth
    ldap : LdapPerson or None
        LDAP record of authenticated user.
    username : str
        UCInetId or full name from LDAP of the authenticated user.
    ucinetid : str
        UCInetId of authenticated user.
    messages : list of str
        Messages returned by WebAuth and LdapPerson.
    url : str
        URL of the web app.

    """
    def __init__(self, request=None, url=None, usrid=None, useldap=True,
                 timeout=None):
        """Initialize backend from request."""
        self.auth = WebAuth()
        self.ldap = None
        self.url = url
        self.messages = []
        self.ucinetid = ''
        self.username = ''

        if request is None:
            # CGI request
            self.environ = os.environ
            remoteaddr = self.environ.get('REMOTE_ADDR')
            if url is None:
                self.url = self._script_url()
        else:
            # Flask request
            self.environ = request.environ
            if request.headers.getlist('X-Forwarded-For'):
                remoteaddr = request.headers.getlist('X-Forwarded-For')[0]
            else:
                remoteaddr = request.remote_addr
            if url is None:
                self.url = request.base_url

        if usrid is None:
            # look in query string and cookies
            usrid = '%s %s' % (self.environ.get('QUERY_STRING'),
                               self.environ.get('HTTP_COOKIE'))

        try:
            self.auth.authenticate(usrid)
            self.auth.validate(timeout=timeout, auth_host=remoteaddr)
        except WebAuthError as e:
            self.messages.append(str(e))
            return
        self.ucinetid = self.username = self.auth.ucinetid

        if useldap:
            try:
                self.ldap = LdapPerson(self.auth.campus_id)
                if self.ldap.pretty_name:
                    self.username = self.ldap.pretty_name
            except LdapPersonError as e:
                self.username = self.ucinetid
                self.messages.append(str(e))

    def __str__(self):
        """Return HTML code for logging in to/out of UCI WebAuth."""
        if self.messages:
            return ('<a href="%s" title="Reason: %s">'
                    'Log in</a> with your UCInetId' % (
                        self.login_url(), escape(self.messages[0])))
        return ('Welcome, <strong>%s</strong> '
                '[ <a href="%s">Log out</a> ]' % (
                    escape(self.username), self.logout_url()))

    def login_url(self):
        """Return URL for logging in to UCI WebAuth system."""
        return self.auth.login_url(self.url)

    def logout_url(self):
        """Return URL for logging out of UCI WebAuth system."""
        return self.auth.logout_url(self.url)

    def logout(self):
        """Log out of UCI WebAuth."""
        self.auth.logout()

    def _script_url(self, pretty_url=False):
        """Return URL of CGI script, without script file name if pretty_url."""
        netloc = self.environ.get('SERVER_NAME')
        port = self.environ.get('SERVER_PORT')
        path = self.environ.get('SCRIPT_NAME')
        if port and port != '80':
            netloc += ':' + port
        if path is None:
            path = self.environ.get('PATH_INFO')
        if path is None:
            path = ''
        elif pretty_url:
            s = path.rsplit('/', 1)
            if '.' in s[-1]:
                path = '/'.join(s[:-1])
        scheme = 'https' if (port and int(port) == 443) else 'http'
        url = urlunsplit([scheme, netloc, path, '', ''])
        url = url.replace(r'//', r'/').replace(r':/', '://')
        return url.lower()


def webauth_test(request=None, url=None):
    """Return HTML response for testing UCI WebAuth authentication."""
    if request is None:
        # CGI request
        import cgi
        args = cgi.FieldStorage()
        args.get = args.getvalue
        form = None
        environ = os.environ
    else:
        # Flask request
        environ = request.environ
        args = request.args
        form = request.form

    auth = WebAuthBackend(request, url)

    html = ['<html><body>',
            '<h1>UCI WebAuth Test</h1>',
            '<p><a href="%s">%s</a></p>' % (auth.url, escape(auth.url)),
            '<p>%s</p>' % auth,
            '<h2>WebAuth Messages</h2><ul>']
    if auth.messages:
        for msg in auth.messages:
            html.append('<li>%s</li>' % escape(msg))
    else:
        html.append('<li>None</li>')
    html.append('</ul>')
    html.append('<h2>WebAuth Record</h2><ul>')
    for item in str(auth.auth).splitlines():
        k, v = item.split('=', 1)
        html.append('<li>%s: <strong>%s</strong></li>' % (k, escape(v)))
    html.append('</ul>')
    html.append('<h2>LDAP Record</h2><ul>')
    if auth.ldap and auth.ldap.cn:
        for item in str(auth.ldap).splitlines():
            k, v = item.split('=', 1)
            html.append('<li>%s: <strong>%s</strong></li>' % (k, escape(v)))
    else:
        html.append('<li>None</li>')
    html.append('</ul>')

    html.append('<h2>Environment Variables</h2><ul>')
    for var in ('AUTH_TYPE', 'AUTH_PASS', 'CONTENT_LENGTH', 'CONTENT_TYPE',
                'DATE_GMT', 'DATE_LOCAL', 'DOCUMENT_NAME', 'DOCUMENT_ROOT',
                'DOCUMENT_URI', 'GATEWAY_INTERFACE', 'LAST_MODIFIED',
                'PATH_INFO', 'PATH_TRANSLATED', 'QUERY_STRING', 'REMOTE_ADDR',
                'REMOTE_HOST', 'REMOTE_IDENT', 'REMOTE_USER', 'REQUEST_METHOD',
                'SCRIPT_NAME', 'SERVER_NAME', 'SERVER_PORT', 'SERVER_PROTOCOL',
                'SERVER_ROOT', 'SERVER_SOFTWARE', 'HTTP_ACCEPT',
                'HTTP_CONNECTION', 'HTTP_HOST', 'HTTP_PRAGMA', 'HTTP_REFERER',
                'HTTP_USER_AGENT', 'HTTP_COOKIE', 'HTTP_ACCEPT_CHARSET',
                'HTTP_ACCEPT_ENCODING', 'HTTP_ACCEPT_LANGUAGE',
                'HTTP_CACHE_CONTROL', 'PATH'):
        value = environ.get(var)
        if value is None:
            value = 'None'
        html.append('<li>%s: <strong>%s</strong></li>' % (
            var, escape(value)))
    html.append('</ul>')

    html.append('<h2>GET Data</h2><ul>')
    if not args:
        html.append('<li>None</li>')
    else:
        for key in args.keys():
            html.append('<li>%s: <strong>%s</strong></li>' % (
                escape(key), escape(args.get(key))))
    html.append('</ul>')

    html.append('<h2>POST Data</h2><ul>')
    if not form:
        html.append('<li>None</li>')
    else:
        for key in form.keys():
            html.append('<li>%s: <strong>%s</strong></li>' % (
                escape(key), escape(form.get(key))))
    html.append('</ul>')

    html.append('</body></html>')
    return '\n'.join(html)


def main():
    """Uciwebauth command line main function for testing."""
    url = 'http://localhost:9000/' + os.path.split(__file__)[-1]
    if os.getenv('SERVER_NAME'):
        import cgitb
        cgitb.enable()
        print('Content-type: text/html\n\n')
        print(webauth_test(url=url))
    elif len(sys.argv) == 3:
        import doctest
        globs = {'TEST_USER': sys.argv[1],  # Enter a UCInetId for testing
                 'TEST_PASSWORD': sys.argv[2]}  # Enter a password for testing
        print(LdapPerson(globs['TEST_USER'],
                         # uid=globs['TEST_USER'],
                         # password=globs['TEST_PASSWORD']
                         ))
        doctest.testmod(verbose=False, extraglobs=globs)
    else:
        import webbrowser
        from http.server import HTTPServer, CGIHTTPRequestHandler
        CGIHTTPRequestHandler.cgi_directories = ['', '/']
        print('Serving CGI script at', url)
        webbrowser.open(url)
        HTTPServer(('localhost', 9000), CGIHTTPRequestHandler).serve_forever()


if __name__ == '__main__':
    sys.exit(main())
