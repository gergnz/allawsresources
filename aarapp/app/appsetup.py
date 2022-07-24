"""Initialise the application"""
import os
import json
import logging
from datetime import timedelta
import boto3
from botocore.exceptions import ClientError
from flask import Flask
from flask.logging import create_logger
from flask_talisman import Talisman
from flask_seasurf import SeaSurf

app = Flask(__name__)

LOG = create_logger(app)

csrf = SeaSurf(app)

SELF = "'self'"
Talisman(app,
        content_security_policy={
        'default-src': SELF,
        'frame-src': [
            SELF,
            'signin.aws.amazon.com',
            'aws.amazon.com'
        ],
        'font-src': [
            SELF,
            'cdn.jsdelivr.net'
        ],
        'img-src': [
            SELF,
            'data:'
        ],
        'object-src': [
            SELF,
            'data:',
            "'unsafe-eval'"
        ],
        'script-src': [
            SELF,
            "'unsafe-eval'",
            'cdn.jsdelivr.net',
            'code.jquery.com',
            'cdn.datatables.net',
            'cdnjs.cloudflare.com'
        ],
        'style-src': [
            SELF,
            "'unsafe-inline'",
            'cdn.jsdelivr.net',
            'code.jquery.com',
            'cdn.datatables.net',
            'cdnjs.cloudflare.com'
        ] } )

app.secret_key = os.getenv('SECRET_KEY')

if app.config['ENV'] == 'development':
    LOG.setLevel(logging.DEBUG)

LOG.propagate = True
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=720)
