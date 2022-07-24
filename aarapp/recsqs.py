#!/usr/bin/env python3
"""Queue processor"""
import os
import json
import logging
import boto3
from sqs_polling import sqs_polling
import resource_scan

logging.basicConfig(level=logging.INFO)

# Use the credentials so we get a list of valid regions from the cross account
boto3session = boto3.session.Session()

def msg_callback(message):
    """deal with the message"""
    logging.info("We got a message: %s", message)

    msg = json.loads(message)

    msg_type = msg['type']
    msg.pop('type')

    if msg_type == 'resources':
        resource_scan.do_main(msg['organisation'])

    logging.info("unknow message type %s, do nothing.", msg_type)
    return True

if __name__ == "__main__":
    your_queue_url=os.environ.get('QUEUE_URL')
    sqs_polling(
            queue_url=your_queue_url,
            visibility_timeout=600,
            interval_seconds=20,
            callback=msg_callback
    )
