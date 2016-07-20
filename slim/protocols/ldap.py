from cStringIO import StringIO
from twisted.logger import Logger
from twisted.internet import defer
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols import pureldap
from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor import entry, entryhelpers
from zope.interface import implements
from slim.protocols.mixins import SupportsEncryptionMixin

logger = Logger()


LDIF = """\
dn: dc=org
dc: org
objectClass: dcObject

dn: dc=example,dc=org
dc: example
objectClass: dcObject
objectClass: organization

dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: cn=bob,ou=people,dc=example,dc=org
cn: bob
gn: Bob
mail: bob@example.org
objectclass: top
objectclass: person
objectClass: inetOrgPerson
sn: Roberts
userPassword: secret

dn: gn=John+sn=Doe,ou=people,dc=example,dc=org
objectClass: addressbookPerson
gn: John
sn: Doe
street: Back alley
postOfficeBox: 123
postalCode: 54321
postalAddress: Backstreet
st: NY
l: New York City
c: US
userPassword: terces

dn: gn=John+sn=Smith,ou=people, dc=example,dc=org
objectClass: addressbookPerson
gn: John
sn: Smith
telephoneNumber: 555-1234
facsimileTelephoneNumber: 555-1235
description: This is a description that can span multi
 ple lines as long as the non-first lines are inden
 ted in the LDIF.
userPassword: eekretsay

"""


class Tree(object):

    def __init__(self):
        self.f = StringIO(LDIF)
        d = fromLDIFFile(self.f)
        d.addCallback(self.ldifRead)

    def ldifRead(self, result):
        self.f.close()
        self.db = result


class LDAPEntry(entry.BaseLDAPEntry,
                entryhelpers.DiffTreeMixin,
                entryhelpers.SubtreeFromChildrenMixin,
                entryhelpers.MatchMixin,
                entryhelpers.SearchByTreeWalkingMixin):

    implements(IConnectedLDAPEntry)

    def __init__(self, dn, attributes={}):
        super(LDAPEntry, self).__init__(dn, attributes)
        self._parent = None
        self._children = []

    def parent(self):
        return self._parent

    def children(self, callback=None):
        if callback is None:
            return defer.succeed(self._children[:])
        else:
            for c in self._children:
                callback(c)
            return defer.succeed(None)

    def _lookup(self, dn):
        if not self.dn.contains(dn):
            raise ldaperrors.LDAPNoSuchObject(dn)
        if dn == self.dn:
            return defer.succeed(self)

        for c in self._children:
            if c.dn.contains(dn):
                return c.lookup(dn)

        raise ldaperrors.LDAPNoSuchObject(dn)

    def lookup(self, dn):
        return defer.maybeDeferred(self._lookup, dn)

    def fetch(self, *attributes):
        return defer.succeed(self)

    def addChild(self, rdn, attributes):
        """TODO ugly API. Returns the created entry."""
        rdn = distinguishedname.RelativeDistinguishedName(rdn)
        for c in self._children:
            if c.dn.split()[0] == rdn:
                raise ldaperrors.LDAPEntryAlreadyExists, c.dn
        dn = distinguishedname.DistinguishedName(
            listOfRDNs=(rdn,) + self.dn.split())
        e = LDAPEntry(dn, attributes)
        e._parent = self
        self._children.append(e)
        return e

    def _delete(self):
        if self._parent is None:
            raise LDAPCannotRemoveRootError
        if self._children:
            raise ldaperrors.LDAPNotAllowedOnNonLeaf, self.dn
        return self._parent.deleteChild(self.dn.split()[0])

    def delete(self):
        return defer.maybeDeferred(self._delete)

    def _deleteChild(self, rdn):
        if not isinstance(rdn, distinguishedname.RelativeDistinguishedName):
            rdn = distinguishedname.RelativeDistinguishedName(stringValue=rdn)
        for c in self._children:
            if c.dn.split()[0] == rdn:
                self._children.remove(c)
                return c
        raise ldaperrors.LDAPNoSuchObject, rdn

    def deleteChild(self, rdn):
        return defer.maybeDeferred(self._deleteChild, rdn)

    def _move(self, newDN):
        if not isinstance(newDN, distinguishedname.DistinguishedName):
            newDN = distinguishedname.DistinguishedName(stringValue=newDN)
        if newDN.up() != self.dn.up():
            # climb up the tree to root
            root = self
            while root._parent is not None:
                root = root._parent
            d = defer.maybeDeferred(root.lookup, newDN.up())
        else:
            d = defer.succeed(None)
        d.addCallback(self._move2, newDN)
        return d

    def _move2(self, newParent, newDN):
        if newParent is not None:
            newParent._children.append(self)
            self._parent._children.remove(self)
        # remove old RDN attributes
        for attr in self.dn.split()[0].split():
            self[attr.attributeType].remove(attr.value)
        # add new RDN attributes
        for attr in newDN.split()[0].split():
            # TODO what if the key does not exist?
            self[attr.attributeType].add(attr.value)
        self.dn = newDN
        return self

    def move(self, newDN):
        return defer.maybeDeferred(self._move, newDN)

    def commit(self):
        return defer.succeed(True)


class EncryptedLDAPServer(LDAPServer):
    def __init__(self):
        LDAPServer.__init__(self)  # fucking old-style classes
        self.startTLS_initiated = False

    def extendedRequest_handleStartTLSRequest(self, request, reply):
        debug_flag = self.debug
        if debug_flag:
            logger.info("Received startTLS request: " + repr(request))
        if self.startTLS_initiated:
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.LDAPOperationsError.resultCode)
            logger.info(
                "Session already using TLS.  "
                "Responding with 'operationsError' (1): " + repr(msg))
        else:
            if debug_flag:
                logger.info("Setting success result code ...")
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.Success.resultCode)
            if debug_flag:
                logger.info("Replying with successful LDAPStartTLSResponse ...")
            reply(msg)
            if debug_flag:
                logger.info("Initiating startTLS on transport ...")
            self.transport.startTLS(self.factory.options)
            self.startTLS_initiated = True
            msg = None
        return defer.succeed(msg)
    extendedRequest_handleStartTLSRequest.oid = pureldap.LDAPStartTLSRequest.oid


class LdapProtocolFactory(ServerFactory, SupportsEncryptionMixin):
    protocol = EncryptedLDAPServer

    def __init__(self, cfg, tls_options, *args):
        self.debug = True
        self.tree = Tree()
        self.root = self.tree.db
        self.options = tls_options
        registerAdapter(
            lambda x: x.root,
            LdapProtocolFactory,
            IConnectedLDAPEntry)

    @property
    def supports_tls(self):
        return True

    @property
    def supports_ssl(self):
        return True

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        return proto
