"""AWS Accounts Model"""
import os
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute

class AWSAccountModel(Model):
    """
    An AWSAccount Model
    """
    class Meta:
        table_name = os.environ.get('ACCOUNTS_TABLE')
        region = os.environ.get('AWS_DEFAULT_REGION')
    organisation = UnicodeAttribute(hash_key=True)
    stsrole = UnicodeAttribute()
    scanrole = UnicodeAttribute()
    externalid = UnicodeAttribute()
