from twisted.web.http import HTTPFactory
from slim.protocols.mixins import SupportsEncryptionMixin


class HttpProtocolFactory(HTTPFactory, SupportsEncryptionMixin):
    def __init__(self, *args):
        super(HttpProtocolFactory, self).__init__()

    @property
    def supports_tls(self):
        return False

    @property
    def supports_ssl(self):
        return True
