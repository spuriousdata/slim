
class SupportsEncryptionMixin(object):
    @property
    def supports_ssl(self):
        raise NotImplementedError

    @property
    def supports_tls(self):
        raise NotImplementedError
