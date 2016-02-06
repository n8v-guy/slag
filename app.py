#!/usr/bin/env python

import os

from flask import Flask
from flask.ext.pymongo import PyMongo

import credentials

app = Flask(__name__)
app.config['MONGO_URI'] = os.environ['MONGOLAB_URI']

mongo = PyMongo(app)

@app.route('/')
def index():
	return str(mongo.db)

@app.route('/crash')
def crash_page():
	raise ValueError('Crash here', 'as planned')

if __name__ == "__main__":
	app.run(host='0.0.0.0', 
		    port=int(os.environ.get('PORT', '8080')),
		    debug=True)
