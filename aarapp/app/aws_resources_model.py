"""AWS Resources Model"""
import os
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, JSONAttribute, UTCDateTimeAttribute, NumberAttribute

class AWSResourcesModel(Model):
    """
    An AWSResources Model
    """
    class Meta:
        table_name = os.environ.get('RESOURCES_TABLE')
        region = os.environ.get('AWS_DEFAULT_REGION')
    organisation = UnicodeAttribute(hash_key=True)
    arn = UnicodeAttribute(range_key=True)
    resourceid = UnicodeAttribute()
    id = UnicodeAttribute()
    tags = JSONAttribute()
    resourcetype = UnicodeAttribute()
    accountid = UnicodeAttribute()
    region = UnicodeAttribute()
    service = UnicodeAttribute()
    created = UTCDateTimeAttribute(null=True)
    found_at = UTCDateTimeAttribute(null=True)
    update_at = UTCDateTimeAttribute(null=True)
    deleted_at = UTCDateTimeAttribute(null=True)
