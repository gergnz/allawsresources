#!/usr/bin/env python3
"""Queue processor"""
import os
import time
import typing
import logging
import datetime
import multiprocessing
import skew
import boto3
import botocore
from app.aws_account_model import AWSAccountModel
from app.aws_resources_model import AWSResourcesModel

logging.basicConfig(level=logging.INFO)

boto3.set_stream_logger('', logging.INFO)


PROCESSES=5

def scan_resources(scan_account):
    """Scan for resources"""
    acts = AWSAccountModel()
    item = acts.get(scan_account['organisation'])


    return {
        'organisation': scan_account['organisation'],
        'accountid': item.stsrole.split(':')[4],
        'arn': item.stsrole,
        'scanrole': item.scanrole,
        'externalid': item.externalid
    }

def get_enabled_regions(boto3_session: boto3.Session, service: str) -> typing.Set[str]:
    """Get valid regions via a bit of a hack"""
    regions = boto3_session.get_available_regions(service)
    enabled_regions = set()
    for region in regions:
        sts_client = boto3_session.client('sts', region_name=region)
        try:
            sts_client.get_caller_identity()
            enabled_regions.add(region)
        except botocore.exceptions.ClientError as exception:
            if exception.response['Error']['Code'] == "InvalidClientTokenId":
                # error code received when region is disabled
                pass
            else:
                raise
    return enabled_regions

def process_tasks(task_queue,details,config):
    """Run the processes"""
    while not task_queue.empty():
        arn = task_queue.get()
        store_skew(arn,details,config)
    return True

def store_skew(arn: str, details, config):
    """Get the data for the region and service, and store it in dynamo"""

    #config = {'accounts':
    #    {details['accountid']:
    #        {'role_arn': details['arn'],
    #         'external_id': details['externalid']
    #        }}}

    logging.info("now scanning: %s", arn)
    # myskewarn = skew.ARN(config=config)
    # skew.ARN.set_logger(myskewarn, 'skew', logging.DEBUG)
    for i in skew.scan(arn, config=config):
        try:
            if i.date is None:
                date = None
            elif isinstance(i.date, int):
                logging.debug("date is in epoch for %s. Converting.", i.arn)
                date = datetime.datetime.utcfromtimestamp(i.date/1000)
            elif isinstance(i.date, str):
                date = datetime.datetime.strptime(i.date, "%Y-%m-%dT%H:%M:%S.%f+0000")
            elif isinstance(i.date, datetime.datetime):
                date = i.date
            else:
                logging.debug(
                        "error no date for %s.",
                        i.arn
                )
                date = None
        except Exception as exception: #pylint: disable=broad-except
            logging.debug(
                    "error setting date for %s with error: %s. Will set date to None.",
                    i.arn,
                    exception
            )
            date = None

        try:
            tags = i.tags
        except Exception as exception: #pylint: disable=broad-except
            logging.debug(
                    "error setting tags for %s with error: %s. Will set tags to nothing.",
                    i.arn,
                    exception
            )
            tags = {}

        try:

            ress = AWSResourcesModel(details['organisation'], i.arn)

            ress.resourceid = ':'.join(i.arn.split(':')[5:])
            ress.id = i.id
            ress.tags = tags
            ress.resourcetype = i.resourcetype
            ress.accountid = i.arn.split(':')[4]
            ress.region = i.arn.split(':')[3]
            ress.service = i.arn.split(':')[2]
            ress.created = date

            ress.save()

        except Exception as exception: #pylint: disable=broad-except
            logging.error(
                    "error saving resource %s using arn filter %s with error: %s",
                    i.arn,
                    arn,
                    exception
            )

def runscan(details, config): #pylint: disable=too-many-locals
    """run a scan"""

    sts = boto3.client('sts')

    assumed_role = sts.assume_role(
        RoleArn=details['arn'],
        RoleSessionName='validregions',
        ExternalId=details['externalid']
    )

    boto3session = boto3.session.Session(
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )
    validregions = get_enabled_regions(boto3session, 's3')
    task_queue = multiprocessing.Queue()

    #config = {'accounts':
    #    {details['accountid']:
    #        {'role_arn': details['arn'],
    #         'external_id': details['externalid']
    #        }}}

    myarn = skew.ARN(config=config)
    myservices = myarn.service.choices()

    for myregion in validregions:
        for myservice in myservices:
            uri = 'arn:aws:' + myservice + ':' + myregion + ':*:*/*'
            task_queue.put(uri)
    processes = []
    logging.info("Running with %s processes!", PROCESSES)
    start = time.time()
    for n_proc in range(PROCESSES): #pylint: disable=unused-variable
        process = multiprocessing.Process(target=process_tasks, args=(task_queue, details, config))
        processes.append(process)
        process.start()
    for process in processes:
        process.join()
    logging.info("Time taken = %s", round(time.time() - start,2))

    return True

def get_accounts(details):
    """Get all the active accounts Id, Name"""
    sts = boto3.client('sts')

    assumed_role = sts.assume_role(
        RoleArn=details['arn'],
        RoleSessionName='getaccounts',
        ExternalId=details['externalid']
    )

    orgs = boto3.client('organizations',
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )

    remotests = boto3.client('sts',
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )

    logging.debug("remote sts: %s", remotests.get_caller_identity())

    all_accounts = orgs.list_accounts()
    active_accounts = {}

    for acc in all_accounts['Accounts']:
        if acc['Status'] != 'ACTIVE':
            continue
        logging.debug("ID:%s, Name:%s", acc['Id'], acc['Name'])
        active_accounts[acc['Id']] = acc['Name']

    return active_accounts

def do_main(organisation):
    """the main function to call"""
    scan_details = scan_resources({
        'organisation': organisation
    })

    accounts_to_scan = get_accounts(scan_details)

    stsrole = boto3.client('sts')

    assumed_stsrole = stsrole.assume_role(
        RoleArn=scan_details['arn'],
        RoleSessionName='getaccounts',
        ExternalId=scan_details['externalid']
    )

    tmpsts = boto3.client('sts',
        aws_access_key_id=assumed_stsrole['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_stsrole['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_stsrole['Credentials']['SessionToken']
    )

    for k in accounts_to_scan:

        tmpconfig = {}
        tmpconfig['accounts'] = {}
        assumed_scanrole = tmpsts.assume_role(
                RoleArn='arn:aws:iam::'+k+':'+scan_details['scanrole'],
                RoleSessionName='scanning',
        )

        tmpconfig['accounts'][k] = {
            'credentials': {
                'aws_access_key_id': assumed_scanrole['Credentials']['AccessKeyId'],
                'aws_secret_access_key': assumed_scanrole['Credentials']['SecretAccessKey'],
                'aws_session_token': assumed_scanrole['Credentials']['SessionToken']
            }
        }
        logging.info("Now scanning account: %s", k)
        runscan(scan_details, tmpconfig)

if __name__ == "__main__":
    do_main(os.environ.get('ORGANISATION'))
