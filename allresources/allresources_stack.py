from aws_cdk import (
    Stack,
    aws_dynamodb as dynamodb,
)
from constructs import Construct

class AllresourcesStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        accountstable = dynamodb.Table(self, 'AccTable',
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="organisation",
                type=dynamodb.AttributeType.STRING
            )
        )

        resourcestable = dynamodb.Table(self, 'RecTable',
            point_in_time_recovery=True,
            partition_key=dynamodb.Attribute(
                name="organisation",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="arn",
                type=dynamodb.AttributeType.STRING
            )
        )
