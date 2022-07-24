"""Manage AWS Accounts"""
from urllib.parse import unquote, quote_plus
import logging
import boto3
from flask import render_template, session, url_for, request, redirect, jsonify, flash
from flask_table import Table, Col, LinkCol
from app.aws_account_model import AWSAccountModel
from app.appsetup import app
from botocore.exceptions import ClientError

def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response

class ButtonCol(Col):
    def td_format(self, content):
        return '<a class="bi bi-trash actions delete-account" data-bs-toggle="modal" data-organisation='+quote_plus(content) +' data-bs-target="#deleteModal"></a>'

class TestCol(LinkCol):
    """A special column for testing."""
    def url(self, item):
        for key in dict(**self.url_kwargs(item)):
            return self.endpoint+';'+key+"="+dict(**self.url_kwargs(item))[key]

class ActsTable(Table): #pylint: disable=abstract-method
    """Show all our accounts."""
    organisation = Col('Organisation Name')
    stsrole = Col('STS Role')
    externalid = Col('External ID')
    scanrole = Col('Scan Role')
    no_items = "No Accounts"
    test = TestCol('Test', '#', url_kwargs=dict(
        organisation='organisation'),
        anchor_attrs={'class': 'bi bi-question-lg actions testaccess'},
        text_fallback=' '
    )
    delete = ButtonCol('Delete')
    classes = ['table', 'table-display', 'table-compact', 'table-hover', 'table-nowrap']
    html_attrs = dict(cellspacing='0', width='100%')
    table_id = 'actstable'

@app.route('/accounts', methods=['GET'])
def accounts():
    """Render page with existing accounts"""

    sts = boto3.client('sts', region_name='ap-southeast-2', endpoint_url='https://sts.ap-southeast-2.amazonaws.com')
    result = sts.get_caller_identity()
    acts = AWSAccountModel()
    #items = acts.query(session['data']['custom:organisation'], AWSAccountModel.arn.startswith('arn'))
    items = acts.scan()
    allitems=[]
    for item in items:
        allitems.append({
            'organisation': item.organisation,
            'stsrole': item.stsrole,
            'scanrole': item.scanrole,
            'externalid': item.externalid,
            'delete': item.organisation
        })

    table = ActsTable(allitems)
    return render_template('accounts.html', actstable=table.__html__(), accid=result['Account'], appenv=app.config['ENV'])

@app.route('/addaws', methods=['POST'])
def addaws():
    """Add a new AWS Organisation"""

    organisation = unquote(request.form.get('organisation'))
    stsrole = unquote(request.form.get('stsrole'))
    externalid = unquote(request.form.get('externalid'))
    scanrole = unquote(request.form.get('scanrole'))

    aws = AWSAccountModel(organisation)
    aws.stsrole=stsrole
    aws.externalid=externalid
    aws.scanrole=scanrole

    try:
        aws.save()
        flash("AWS Organisation successfully added.", "success")
    except Exception as error: #pylint: disable=broad-except
        logging.error(error)
        flash("Failed to add AWS Organisation.", "danger")

    response = redirect(url_for("accounts"))
    return response

@app.route('/delaws', methods=['GET'])
def delaws():
    """Delete an AWS Account"""
    organisation = unquote(request.args.get('organisation'))

    acts = AWSAccountModel()
    acts_item = acts.get(organisation)
    try:
        acts_item.delete()
        flash("AWS Organisation successfully deleted.", "success")
    except Exception as error: #pylint: disable=broad-except
        logging.error(error)
        flash("Failed to delete AWS Organisation.", "danger")

    response = redirect(url_for("accounts"))
    return response

@app.route('/testaccess', methods=['GET'])
def testaccess():
    """Check we can assume and get our identity."""

    organisation = unquote(request.args.get('organisation'))
    acts = AWSAccountModel()
    item = acts.get(organisation)

    sts = boto3.client('sts')

    try:
        assumed_role = sts.assume_role(
            RoleArn=item.stsrole,
            ExternalId=item.externalid,
            RoleSessionName='accesstest'
        )
        teststs = boto3.client('sts',
            aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
            aws_session_token=assumed_role['Credentials']['SessionToken']
        )
        result = teststs.get_caller_identity()
        response = {'result': 'success', 'identity': result}
    except Exception as error: #pylint: disable=broad-except
        response = {'result': 'failed', 'error': str(error)}

    return jsonify(response)
