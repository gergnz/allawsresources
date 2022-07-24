#!/usr/bin/env python3
"""Queue processor"""
import os
import json
import logging
import boto3
from sqs_polling import sqs_polling
from start_task import start_task

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
        msg['tasktype'] = 'resources'
        msg['cpu'] = '4096'
        msg['memory'] = '8192'
        msg['command'] = './resource_scan.py'
        return start_task(msg)

    if msg_type == 'deployconfig':
        msg['tasktype'] = 'deployconfig'
        msg['command'] = './deploy_config.py'
        return start_task(msg)

    if msg_type == 'setupsns':
        msg['tasktype'] = 'setupsns'
        msg['command'] = './setupsns.py'
        return start_task(msg)

    if msg_type == 'deploysecurityhub':
        msg['tasktype'] = 'deploysecurityhub'
        msg['command'] = './enable_securityhub.py'
        return start_task(msg)

    if msg_type == 'deploysharr':
        msg['tasktype'] = 'deploysharr'
        msg['command'] = './deploy_sharr.py'
        return start_task(msg)

    if msg_type == 'cleanaccount':
        msg['tasktype'] = 'cleanaccount'
        return start_task(msg)

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
