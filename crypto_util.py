"""Utils for encrypt/decrypt"""
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    """Class to encode/decode strings with the same key on AES cipher"""

    def __init__(self, key):
        """Despite key is passed, wrap it with key-derivation function"""
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, value):
        """Encrypt value with AES plus key from constructor"""
        value = self._add_pad(value)
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        return base64.b64encode(init_vector + cipher.encrypt(value))

    def decrypt(self, enc):
        """Decrypt value with AES plus key from constructor"""
        enc = base64.b64decode(enc)
        init_vector = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        result = cipher.decrypt(enc[AES.block_size:])
        return self._del_pad(result)

    @staticmethod
    def _add_pad(value):
        key_size = 16
        pad_size = key_size - len(value) % key_size
        new_size = pad_size + len(value)
        return value.ljust(new_size, chr(pad_size))

    @staticmethod
    def _del_pad(value):
        return value[:-ord(value[-1])]
