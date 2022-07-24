import json
import urllib
from urllib.parse import unquote
import logging
import requests
import boto3
from flask import render_template, session, abort, redirect, request, url_for, flash
from flask_table import Table, Col, LinkCol
from app.aws_account_model import AWSAccountModel
from app.appsetup import app

class ActsTable(Table): #pylint: disable=abstract-method
    organisation = Col('Organisaation')
    stsrole = Col('STS Role')
    externalid = Col('External ID')
    assume = LinkCol('Assume Role', 'assumerole', url_kwargs=dict(
        stsrole='stsrole', externalid='externalid'),
        anchor_attrs={'class': 'bi bi-columns primary actions'},
        text_fallback=' '
    )
    classes = ['table', 'table-display', 'table-compact', 'table-hover', 'table-nowrap']
    html_attrs = dict(cellspacing='0', width='100%')
    table_id = 'allaccounts'

@app.route('/scooby', methods=['GET'])
def scooby():
    acts = AWSAccountModel()
    items = acts.scan()
    allitems=[]
    for item in items:
        allitems.append({
            'organisation': item.organisation,
            'stsrole': item.stsrole,
            'externalid': item.externalid,
        })

    table = ActsTable(allitems)
    return render_template('scooby.html', allaccounts=table.__html__())

@app.route('/assumerole', methods=['GET'])
def assumerole():
    sts_connection = boto3.client('sts')

    try:
        assumed_role_object = sts_connection.assume_role(
            RoleArn=unquote(request.args.get('stsrole')),
            RoleSessionName="Console",
            ExternalId=unquote(request.args.get('externalid'))
        )
    except Exception as error: #pylint: disable=broad-except
        flash("Failed to assume role.", "danger")
        logging.error(str(error))
        return redirect(url_for('scooby'))

    url_credentials = {}
    url_credentials['sessionId'] = assumed_role_object.get('Credentials').get('AccessKeyId')
    url_credentials['sessionKey'] = assumed_role_object.get('Credentials').get('SecretAccessKey')
    url_credentials['sessionToken'] = assumed_role_object.get('Credentials').get('SessionToken')
    json_string_with_temp_credentials = json.dumps(url_credentials)

    request_parameters = "?Action=getSigninToken"
    request_parameters += "&SessionDuration=1800"
    def quote_plus_function(qps):
        return urllib.parse.quote_plus(qps)

    request_parameters += "&Session=" + quote_plus_function(json_string_with_temp_credentials)
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters
    r_url = requests.get(request_url)
    signin_token = json.loads(r_url.text)

    request_parameters = "?Action=login"
    request_parameters += "&Issuer=Example.org"
    request_parameters += "&Destination=" + quote_plus_function("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + signin_token["SigninToken"]
    request_url = "https://signin.aws.amazon.com/federation" + request_parameters

    return redirect(request_url)
