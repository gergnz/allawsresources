"""Build the resources page"""
import os
import json
from urllib.parse import unquote
from flask import flash, render_template, session, request, redirect, url_for
from flask_table import Table, Col, NestedTableCol
import boto3
from app.aws_account_model import AWSAccountModel
from app.aws_resources_model import AWSResourcesModel
from app.appsetup import app

class TagTable(Table): #pylint: disable=abstract-method
    key = Col('Key')
    value = Col('Value')
    table_id = 'tagstable'

class ItemTable(Table): #pylint: disable=abstract-method
    arn = Col('ARN')
    accountid = Col('AccountID')
    resourcetype = Col('Resource Type')
    created = Col('Created At')
    region = Col('Region')
    service = Col('Service')
    tags = NestedTableCol('tags', TagTable)
    classes = ['table', 'table-striped', 'table-bordered']
    html_attrs = dict(cellspacing='0', width='100%')
    table_id = 'allawsresources'

def start_scan():
    organisation = unquote(request.form.get('organisation', 'BLANK'))

    if organisation == 'BLANK':
        flash("No Organisation supplied.", "danger")
        response = redirect(url_for("resources"))
        return response

    message = {
            "type": 'resources',
            "organisation": organisation,
    }

    sqs = boto3.client('sqs')

    sqs.send_message(
        QueueUrl=os.environ.get('QUEUE_URL'),
        MessageBody=json.dumps(message)
    )

    flash("Scan started!", "success")
    response = redirect(url_for("resources"))
    return response

@app.route('/resources', methods=['GET', 'POST'])
def resources():

    if request.method == 'POST':
        return start_scan()

    acts = AWSAccountModel()
    ress = AWSResourcesModel()
    items = acts.scan()

    all_organisations = []

    for item in items:
        all_organisations.append(item.organisation)

    allitems = []

    my_resources = ress.query(all_organisations[0])

    for resource in my_resources:
        tags = []
        print(resource.arn)
        for k in resource.tags:
            tags.append({'key': k, 'value': resource.tags[k]})
        print("################################################################")

        allitems.append({
            'arn': resource.arn,
            'accountid': resource.accountid,
            'resourcetype': resource.resourcetype,
            'created': resource.created,
            'region': resource.region,
            'service': resource.service,
            'tags': tags
        })

    table = ItemTable(allitems)
    return render_template('resources.html', allitems=table.__html__(), all_organisations=all_organisations)
