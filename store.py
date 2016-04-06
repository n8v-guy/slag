"""Utils to work with mongodb memory-cached collections"""
import time
import crypto
import mongo_store


class TokenStore(mongo_store.MongoStore):
    """Encrypted tokens store"""

    def __init__(self, collection, context, key):
        super(TokenStore, self).__init__(collection, context)
        self._cipher = crypto.AESCipher(key)
        self._tokens = {self._cipher.decrypt(enc): enc for enc in self.keys()}

    @staticmethod
    def record(user, full_access):
        """create dict of known data"""
        return {
            'user': user['user_id'],
            'last_check': time.time(),
            'full_access': full_access,  # extended scope
            'login': user['user']  # duplicate field for debug purpose
        }

    def upsert(self, token, user, full_access=None):
        """
        Update/insert token/record pair
        :param token: access token to store encrypted
        :param user: API answer for identify check
        :param full_access: can be None for saving previous full_access value
        :returns: user auth key
        """
        if token in self._tokens.keys():
            key = self._tokens[token]
        else:
            key = self._cipher.encrypt(token)
            self._tokens[token] = key
        if full_access is None:
            assert key in self, 'full_access can be None only for existing key'
            full_access = self[key].get('full_access', False)
        rec = TokenStore.record(user, full_access)
        self[key] = rec
        return key

    def is_known_token(self, token):
        """Check if this token saved already"""
        return token in self._tokens.keys()

    def is_known_user(self, enc_key):
        """Check if this encrypted key is genuine"""
        return enc_key in self.keys()

    def decrypt_keys_map(self):
        """:returns: 'token to encoded' map"""
        return dict(self._tokens)

    def get_key_by_known_token(self, token):
        """:returns: encoded key by plain token"""
        if token in self._tokens.keys():
            return self._tokens[token]
        raise ValueError('Unknown token')

    def get_user(self, enc_key):
        """:returns: value associated with encrypted key"""
        if self.is_known_user(enc_key):
            return self[enc_key]
        raise KeyError()
