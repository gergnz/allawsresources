from aws_cdk import (
    Stack,
    aws_kms as kms,
    aws_sqs as sqs,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_ecr as ecr,
    aws_ssm as ssm,
    aws_logs as logs,
    aws_route53 as r53,
    aws_dynamodb as dynamodb,
    aws_certificatemanager as acm,
    aws_elasticloadbalancingv2 as elbv2,
    aws_secretsmanager as secretsmanager,
    aws_ecs_patterns as ecs_patterns
)

from constructs import Construct

class AllresourcesStack(Stack):

    def create_kms_key(self, alias: str):
        return kms.Key(
            self, 
            f'{alias}-key',
            alias=alias
        )
    
    def create_dynamodb_table(self, name: str, partition_key: dynamodb.Attribute = None, sort_key: dynamodb.Attribute = None, encryption_key: kms.Key = None):
        return dynamodb.Table(
            self, 
            id=name,
            table_name=name,
            point_in_time_recovery=True,
            partition_key=partition_key,
            sort_key=sort_key,
            encryption_key=encryption_key
        )

    def __init__(self, scope: Construct, construct_id: str, config: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        region = Stack.of(self).region
        resource_prefix = config['resource_prefix']

        # KMS -> Create Key
        allawsresources_key = self.create_kms_key(f'{resource_prefix}/aar')
        
        # ECR -> Repository Lookup
        ecr_repository = ecr.Repository.from_repository_name(
            self,
            id=f'{resource_prefix}-aar',
            repository_name=config['ecr']['repository_name']
        )

        # R53 -> Hosted Zone Lookup
        hosted_zone = r53.HostedZone.from_hosted_zone_attributes(
            self,
            id=f'{resource_prefix}-hosted-zone-lookup',
            hosted_zone_id=config['route53']['hosted_zone_id'],
            zone_name=config['route53']['hosted_zone_name']
        )
           
        # DynamoDB -> Create Accounts Table
        accounts_table = self.create_dynamodb_table(
            name=f'{resource_prefix}-aar-acc-table',
            partition_key=dynamodb.Attribute(
                name="organisation", type=dynamodb.AttributeType.STRING
            ),
            encryption_key=allawsresources_key
        )

        # DynamoDB -> Create Resources Table
        resources_table = self.create_dynamodb_table(
            name=f'{resource_prefix}-aar-rec-table',
            partition_key=dynamodb.Attribute(
                name="organisation", 
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="arn", 
                type=dynamodb.AttributeType.STRING
            ),
            encryption_key=allawsresources_key
        )

        # SQS -> Create Queue
        sqs_queue = sqs.Queue(
            self, 
            id=f'{resource_prefix}-aar-resource-sqs',
            queue_name=f'{resource_prefix}-aar-resource-sqs',
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=allawsresources_key
        )

        # Secrets Manager -> Create Secret
        secret = secretsmanager.Secret(
            self,
            id=f'{resource_prefix}-aar/ecs',
            secret_name=f'{resource_prefix}-aar/ecs',
            encryption_key=allawsresources_key
        )

        # Secrets Manager -> Secret Lookup
        ecs_secrets = secretsmanager.Secret.from_secret_name_v2(
            self, 
            id=f'{resource_prefix}-secret-lookup', 
            secret_name=secret.secret_name
        )

        # VPC -> VPC Lookup
        vpc = ec2.Vpc.from_lookup(
            self,
            id=f'{resource_prefix}-vpc',
            vpc_id=ssm.StringParameter.value_from_lookup(
                self,
                parameter_name=config['vpc']['vpc_id_ssm'],
            ),
        )

        # CloudWatch -> Log Group Lookup
        log_group = logs.LogGroup.from_log_group_name(
            self,
            id=f'{resource_prefix}-aar-ecs-log-group-lookup',
            log_group_name=f'{resource_prefix}-aar-ecs'
        )

        # IAM -> Create Execution Role
        execution_role = iam.Role(
            self, 
            id=f'{resource_prefix}-aar-ecs-execution-role',
            assumed_by=iam.ServicePrincipal("ecs-tasks"),
            role_name=f'{resource_prefix}-aar-ecs-execution-role'
        )

        # IAM -> Create Execution Role Policy
        execution_role_policy = iam.Policy(
            self,
            id=f'{resource_prefix}-aar-ecs-execution-policy',
            policy_name=f'{resource_prefix}-aar-ecs-execution-policy',
            statements=[
                iam.PolicyStatement(
                    resources=["*"],
                    actions=["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability", "sts:*", "dynamodb:ListTables", "kms:ListKeys", "kms:ListAliases"]
                ),
                iam.PolicyStatement(
                    resources=[secret.secret_full_arn],
                    actions=["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:ListSecretVersionIds", "secretsmanager:GetResourcePolicy"]
                ),
                iam.PolicyStatement(
                    resources=[allawsresources_key.key_arn],
                    actions=["kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*", "kms:DescribeKey", "kms:GenerateDataKey"]
                ),
            ])

        execution_role_policy.attach_to_role(execution_role)

        # IAM -> Create Task Role
        task_role = iam.Role(
            self, 
            id=f'{resource_prefix}-aar-ecs-task-role',
            assumed_by=iam.ServicePrincipal("ecs-tasks"),
            role_name=f'{resource_prefix}-aar-ecs-task-role'
        )

        # IAM -> Create Task Role Policy
        task_role_policy = iam.Policy(
            self,
            id=f'{resource_prefix}-aar-ecs-task-policy',
            policy_name=f'{resource_prefix}-aar-ecs-task-policy',
            statements=[
                iam.PolicyStatement(
                    resources=[
                        f"arn:aws:dynamodb:*:*:table/{accounts_table.table_name}/index/*",
                        f"arn:aws:dynamodb:*:*:table/{resources_table.table_name}/index/*",
                        f"arn:aws:dynamodb:*:*:table/{accounts_table.table_name}",
                        f"arn:aws:dynamodb:*:*:table/{resources_table.table_name}"
                    ],
                    actions=["dynamodb:PutItem","dynamodb:DescribeTable", "dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query", "dynamodb:UpdateItem"]
                ),
                iam.PolicyStatement(
                    resources=[allawsresources_key.key_arn],
                    actions=["kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*", "kms:DescribeKey", "kms:GenerateDataKey"]
                ),
                iam.PolicyStatement(
                    resources=['*'],
                    actions=["sts:*"]
                ),
                iam.PolicyStatement(
                    resources=[sqs_queue.queue_arn],
                    actions=["sqs:*"]
                ),
        ])

        task_role_policy.attach_to_role(task_role)


        # ECS -> Create Cluster
        cluster = ecs.Cluster(
            self, 
            id=f'{resource_prefix}-aar-cluster', 
            vpc=vpc, 
            cluster_name=f'{resource_prefix}-aar-cluster'
        )

        # ECS -> Create Task Definition
        task_definition = ecs.FargateTaskDefinition(
            self,
            id=f'{resource_prefix}-aar-fargate-td',
            memory_limit_mib=4096,
            cpu=2048,
            task_role=task_role,
            execution_role=execution_role,
            family=f'{resource_prefix}-aar-fargate-td',
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.ARM64
            )
        )

        # Secrets Manager -> Secret Retrieval
        secrets = {}
        for secret in config['secrets']['variables']:
            secrets[secret] = ecs.Secret.from_secrets_manager(ecs_secrets, secret)
            
        # ECS -> Task Definition -> Container
        container = task_definition.add_container(
            id=f'{resource_prefix}-aar-container',
            image=ecs.ContainerImage.from_registry(f'{ecr_repository.repository_uri}:latest'),
            container_name=f'{resource_prefix}-aar-container',
            working_directory='/srv',
            entry_point=["supervisord","-c","/srv/supervisor.conf"],
            environment={
                "RESOURCES_TABLE": resources_table.table_name,
                "ACCOUNTS_TABLE": accounts_table.table_name,
                "AWS_DEFAULT_REGION": region,
                "QUEUE_URL": sqs_queue.queue_url,
                "ENV": "development"
            },
            secrets=secrets,
            logging=ecs.LogDriver.aws_logs(
                stream_prefix='ecs', 
                log_group=log_group
            ),
        )
      
        # Container -> Port Mappings
        container.add_port_mappings(
            ecs.PortMapping(
                container_port=5000,
                host_port=5000,
                protocol=ecs.Protocol.TCP,
            )
        )
        
        # ECS -> Cluster -> Fargate Service
        #
        # Note: Using ecs.FargateTaskDefinition instead of ApplicationLoadBalancedTaskImageOptions
        #       as the following options are currently missing:
        #
        #       * Unable to define working directory and entry point
        #       * Unable to specify container runtime platform
        #
        fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            id=f'{resource_prefix}-aar-service',
            cluster=cluster,
            service_name=f'{resource_prefix}-aar-service',
            task_definition=task_definition,
            task_subnets=ec2.SubnetSelection(
                subnet_filters=[
                    ec2.SubnetFilter.by_ids(config['vpc']['subnets'])
                ]
            ),
            assign_public_ip=False,
            load_balancer_name=f'{resource_prefix}-aar-int-alb',
            redirect_http=True,
            listener_port=443,
            certificate=acm.Certificate(
                self,
                id=f'{resource_prefix}-aar-certificate',
                domain_name=config['route53']['domain'],
                validation=acm.CertificateValidation.from_dns(
                    hosted_zone=hosted_zone
                )
            ),
            domain_name=config['route53']['domain'],
            domain_zone=hosted_zone
        )

        # Load Balancer -> Select Subnets
        fargate_service.load_balancer.vpc_subnets = ec2.SubnetSelection(
            subnet_filters=[
                ec2.SubnetFilter.by_ids(config['vpc']['subnets'])
            ]
        )

        fargate_service.target_group.health_check = elbv2.HealthCheck(
            healthy_http_codes="200,302"
        )
    