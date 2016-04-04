"""Just a converter from mongo collection to dictionary with _id as the key"""
import collections
import werkzeug.datastructures as datastruct
PRIMARY_KEY = '_id'


class MongoStore(collections.MutableMapping):
    """gets collection, creates dictionary, commit on changes"""

    @staticmethod
    def _make_dict(value):
        """return immutable dict without PRIMARY_KEY key"""
        return datastruct.ImmutableDict({
            k: v for k, v in value.iteritems() if k != PRIMARY_KEY
            })

    def __init__(self, mongo_collection, context):
        """
        read collection to dictionary
        :param mongo_collection: pymongo collection
        :param context: context manager for collection operations
        """
        self._collection = mongo_collection
        self._context = context
        with self._context:
            rows = tuple(self._collection.find({}))
        self._store = {
            row[PRIMARY_KEY]: MongoStore._make_dict(row) for row in rows
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
        del value[PRIMARY_KEY]
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
            raise KeyError()
        value = dict(self._store[key])
        value[field] = field_value
        self[key] = value

    def __delitem__(self, key):
        """remove row from collection by key"""
        if key not in self._store.keys():
            raise KeyError()
        with self._context:
            self._collection.delete_one({PRIMARY_KEY: key})
        del self._store[key]

    def __getitem__(self, key):
        """read value by key from collection"""
        return self._store[key]

    def get_row(self, key):
        """read row by key from collection"""
        row = dict(self._store[key])
        row.update({PRIMARY_KEY: key})
        return row

    def __len__(self):
        """getting row count of collection"""
        return len(self._store)

    def __iter__(self):
        """collection iterator"""
        return self._store.__iter__()
