"""Just a converter from mongo collection to dictionary with _id as the key"""
import collections
import werkzeug.datastructures as datastruct
PRIMARY_KEY = '_id'


class MongoStore(collections.MutableMapping):
    """gets collection, creates dictionary, commit on changes"""

    @staticmethod
    def _make_dict(value):
        """return ImmutableDict without PRIMARY_KEY key"""
        return datastruct.ImmutableDict({
            k: v for k, v in value.iteritems() if k != PRIMARY_KEY
            })

    def __init__(self, mongo_collection):
        """
        read collection to dictionary
        :param mongo_collection: flask_pymongo.wrappers.Collection
        """
        self.collection = mongo_collection
        rows = tuple(self.collection.find({}))
        self.store = {
            row[PRIMARY_KEY]: MongoStore._make_dict(row) for row in rows
        }

    def __setitem__(self, key, value):
        """
        store value to collection if any difference found
        :param key: primary key for collection
        :param value: value to store for this key in collection
        """
        assert PRIMARY_KEY not in value or value[PRIMARY_KEY] == key
        # copy before write
        value = dict(value)
        value[PRIMARY_KEY] = key
        # do nothing on no changes
        if key in self.store.keys() and value == self.store[key]:
            return
        del value[PRIMARY_KEY]
        self.collection.find_one_and_replace(
            {PRIMARY_KEY: key},
            value,
            upsert=True
        )
        self.store[key] = datastruct.ImmutableDict(value)

    def __delitem__(self, key):
        """
        read row by key from collection
        :param key: key to remove in collection
        """
        if key not in self.store.keys():
            raise KeyError
        self.collection.delete_one({PRIMARY_KEY: key})
        del self.store[key]

    def __getitem__(self, key):
        """
        read value from collection if exist
        :param key: key to find in collection
        """
        return self.store[key]

    def __len__(self):
        """getting row count of collection"""
        return len(self.store)

    def __iter__(self):
        """collection iterator"""
        return self.store.__iter__()
