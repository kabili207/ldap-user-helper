# import needed modules
import hashlib
import os
import ldap
import ldap.modlist as modlist
import getpass

from sys import version_info

class LdapHelper:

  def __init__(self, url, basedn, manager, passwd):
    self.url = url
    self.basedn = basedn
    self.manager = manager
    self.password = passwd

  def connect(self):
    self.connection = ldap.initialize("ldap://localhost:389/")
    self.connection.simple_bind_s(self.manager, self.password)

  def close(self):
    self.connection.unbind_s()

  @staticmethod
  def make_secret(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    """
    salt = os.urandom(4)

    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)

    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()

    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)

    return tagged_digest_salt

  @staticmethod
  def get_input(prompt, default=''):
    if version_info[0] > 2:
        response = input("{} [{}]: ".format(prompt, default))
    else:
        response = raw_input("{} [{}]: ".format(prompt, default))
    return response or default

  def get_id(self, id):
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    searchFilter = "cn=nextIds"
    next_id = -1
    id_dn = searchFilter + "," + self.basedn

    l = self.connection

    try:
        ldap_result_id = l.search(self.basedn, searchScope, searchFilter, retrieveAttributes)
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    # Get the next ID
                    next_id = int(result_data[0][1][id][0])
                    # And increment it for the next time
                    id_ldif = [ ( ldap.MOD_REPLACE, id, str(next_id + 1) ) ]
                    l.modify_s(id_dn, id_ldif)

        if next_id == -1:

            # A dict to help build the "body" of the object
            id_attrs = {}
            id_attrs['objectclass'] = ['top', 'unixIdPool']
            id_attrs['cn'] = 'nextIds'
            id_attrs['uidNumber'] = '10000'
            id_attrs['gidNumber'] = '10000'

            id_ldif = modlist.addModlist(id_attrs)

            # Do the actual synchronous add-operation to the ldapserver
            l.add_s(id_dn, id_ldif)
            next_id = 10000

    except ldap.LDAPError, e:
        print(e)

    return next_id

  def create_user(self, username, password, fullname, gidnumber, homedir, shell='/bin/bash', description=''):
    # The dn of our new entry/object
    dn="uid={},ou=People,{}".format(username, self.basedn)

    uidnumber = self.get_id('uidNumber')

    # A dict to help build the "body" of the object
    attrs = {}
    attrs['objectclass'] = ['top', 'account', 'posixAccount', 'shadowAccount']
    attrs['cn'] = fullname
    attrs['uid'] = username
    attrs['uidNumber'] = str(uidnumber)
    attrs['gidNumber'] = str(gidnumber)
    attrs['homeDirectory'] = homedir
    attrs['loginShell'] = shell
    attrs['description'] = description
    attrs['gecos'] = fullname + ',,,'
    attrs['userPassword'] = LdapHelper.make_secret(password)
    attrs['shadowLastChange'] = '0'
    attrs['shadowMax'] = '99999'
    attrs['shadowWarning'] = '99999'

    # Convert our dict to nice syntax for the add-function using modlist-module
    ldif = modlist.addModlist(attrs)

    # Do the actual synchronous add-operation to the ldapserver
    self.connection.add_s(dn,ldif)

    return uidnumber

  def create_group(self, groupname, description):
    # The dn of our new entry/object
    dn="cn={},ou=Group,{}".format(groupname, self.basedn)

    gidnumber = self.get_id('gidNumber')

    # A dict to help build the "body" of the object
    attrs = {}
    attrs['objectclass'] = ['top', 'groupOfNames', 'posixGroup']
    attrs['cn'] = groupname
    attrs['gidNumber'] = str(gidnumber)
    attrs['description'] = description
    attrs['member'] = 'cn=DELETE_ME' # member is a required attribute

    # Convert our dict to nice syntax for the add-function using modlist-module
    ldif = modlist.addModlist(attrs)

    # Do the actual synchronous add-operation to the ldapserver
    self.connection.add_s(dn,ldif)

    return gidnumber
