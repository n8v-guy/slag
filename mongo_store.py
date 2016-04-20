"""Just a converter from mongo collection to dictionary with _id as the key"""
import collections
import werkzeug.datastructures as datastruct
PRIMARY_KEY = '_id'


class MongoStore(collections.MutableMapping):
    """gets collection, creates dictionary, commit on changes"""

    def __init__(self, mongo_collection, context):
        """
        :param mongo_collection: collection to read/cache
        :param context: context manager for collection operations
        """
        self._collection = mongo_collection
        self._context = context
        self._store = {}
        self.reload()

    def reload(self):
        """read collection to dictionary"""
        with self._context:
            rows = tuple(self._collection.find({}))
            self._store = {
                row[PRIMARY_KEY]: datastruct.ImmutableDict(row) for row in rows
            }

    def __setitem__(self, key, value):
        """store key-value to collection (lazy if value isn't changed)"""
        assert PRIMARY_KEY not in value or value[PRIMARY_KEY] == key
        # copy before write
        value = dict(value)
        value[PRIMARY_KEY] = key
        # do nothing on no changes
        if key in self._store.keys() and value == self._store[key]:
            return
        with self._context:
            self._collection.find_one_and_replace(
                {PRIMARY_KEY: key},
                value,
                upsert=True
            )
        self._store[key] = datastruct.ImmutableDict(value)

    def set_field(self, key, field, field_value):
        """Set single field in value dict, as value is immutable"""
        if key not in self._store:
            raise KeyError(key)
        value = dict(self._store[key])
        value[field] = field_value
        self[key] = value

    def __delitem__(self, key):
        """remove row from collection by key"""
        if key not in self._store.keys():
            raise KeyError(key)
        with self._context:
            self._collection.delete_one({PRIMARY_KEY: key})
        del self._store[key]

    def __getitem__(self, key):
        """read value by key from collection"""
        return self._store[key]

    def __len__(self):
        """getting row count of collection"""
        return len(self._store)

    def __iter__(self):
        """collection iterator"""
        return self._store.__iter__()
