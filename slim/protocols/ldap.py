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


class EncryptedLDAPServer(LDAPServer):
    def __init__(self):
        LDAPServer.__init__(self)  # fucking old-style classes
        self.startTLS_initiated = False

    def extendedRequest_handleStartTLSRequest(self, request, reply):
        """
        If the protocol factory has an `options` attribute it is assumed
        to be a `twisted.internet.ssl.CertificateOptions` that can be used
        to initiate TLS on the transport.

        Otherwise, this method returns an `unavailable` result code.
        """
        debug_flag = self.debug
        if debug_flag:
            logger.info("Received startTLS request: " + repr(request))
        if hasattr(self.factory, 'options'):
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
        else:
            msg = pureldap.LDAPStartTLSResponse(
                resultCode=ldaperrors.LDAPUnavailable.resultCode)
            logger.info(
                "StartTLS not implemented.  "
                "Responding with 'unavailable' (52): " + repr(msg))
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
