import os

from flask import Flask
from flask.ext.pymongo import PyMongo

import credentials

app = Flask(__name__)
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']

mongo = PyMongo(app)

@app.route('/')
def index():
	return mongo.server_info()

if __name__ == "__main__":
	app.run(debug=True)
