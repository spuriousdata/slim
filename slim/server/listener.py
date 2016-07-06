import sys
from twisted.python import log
from twisted.internet import reactor, ssl
from OpenSSL.SSL import SSLv23_METHOD
from slim.utils import config, get_class_from_string


class Listener(object):
    def __init__(self):
        log.startLogging(sys.stdout)
        self.db = get_class_from_string(config.db.driver)(config.db)

    def run(self):
        if config._get(config, 'sslcert', False):
            with open(config.sslcert.certificate_file, 'rb') as fp:
                cert = fp.read()

            certificate = ssl.PrivateCertificate.loadPEM(cert)
            co = certificate.options()
            ssl_cert_options = ssl.CertificateOptions(co.privateKey, co.certificate, method=SSLv23_METHOD)
            tls_cert_options = co

        for proto_config in config.protocols:
            factory = get_class_from_string(proto_config.factory)(proto_config, tls_cert_options)

            if proto_config.ssl and factory.supports_ssl:
                reactor.listenSSL(proto_config.ssl.port, factory, ssl_cert_options)

            if config._get(proto_config, 'transport') and proto_config.transport.lower() == 'udp':
                reactor.listenUDP(proto_config.port, factory)
            elif config._get(proto_config, 'tls') and proto_config.tls.enable and factory.supports_tls:
                factory.options = tls_cert_options
                reactor.listenTCP(proto_config.port, factory)
            else:
                reactor.listenTCP(proto_config.port, factory)

        reactor.run()
