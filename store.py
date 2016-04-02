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

    def upsert(self, token, user, full_access):
        """Update/insert token/record pair"""
        rec = TokenStore.record(user, full_access)
        if token in self._tokens.keys():
            key = self._tokens[token]
        else:
            key = self._cipher.encrypt(token)
        self.__setitem__(key, rec)

    def is_known_token(self, token):
        """Check if this token saved already"""
        return token in self._tokens.keys()
