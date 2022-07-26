from aws_cdk import (
    Stack,
    Duration,
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
    aws_route53_targets as r53targets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_secretsmanager as secretsmanager
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

        # Create KMS Key
        allawsresources_key = self.create_kms_key(f'{resource_prefix}/aar')
        
        # Lookup ECR Repository
        ecr_repository = ecr.Repository.from_repository_name(
            self,
            id=f'{resource_prefix}-aar',
            repository_name=config['ecr']['repository_name']
        )

        # DynamoDB 

        ## Accounts Table
        accounts_table = self.create_dynamodb_table(
            name=f'{resource_prefix}-aar-acc-table',
            partition_key=dynamodb.Attribute(
                name="organisation", type=dynamodb.AttributeType.STRING
            ),
            encryption_key=allawsresources_key
        )

        ## Resources Table
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

        # SQS Queue
        sqs_queue = sqs.Queue(
            self, 
            id=f'{resource_prefix}-aar-resource-sqs',
            queue_name=f'{resource_prefix}-aar-resource-sqs',
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=allawsresources_key
        )

        # Secrets Manager Repository
        secret = secretsmanager.Secret(
            self,
            id=f'{resource_prefix}-aar/ecs',
            secret_name=f'{resource_prefix}-aar/ecs',
            encryption_key=allawsresources_key
        )

        ecs_secrets = secretsmanager.Secret.from_secret_name_v2(
            self, 
            id="resource-secret-lookup", 
            secret_name=secret.secret_name
        )

        # VPC Lookup
        vpc = ec2.Vpc.from_lookup(
            self,
            id=f'{resource_prefix}-vpc',
            vpc_id=ssm.StringParameter.value_from_lookup(
                self,
                parameter_name=config['vpc']['vpc_id_ssm'],
            ),
        )

        # ECS Cluster
        cluster = ecs.Cluster(
            self, 
            id=f'{resource_prefix}-aar-cluster', 
            vpc=vpc, 
            cluster_name=f'{resource_prefix}-aar-cluster'
        )

        ## ECS Cluster -> Execution Role
        execution_role = iam.Role(
            self, 
            id=f'{resource_prefix}-aar-ecs-execution-role',
            assumed_by=iam.ServicePrincipal("ecs-tasks"),
            role_name=f'{resource_prefix}-aar-ecs-execution-role'
        )
        # ECS Cluster -> Execution Role -> Execution Role Policy
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

        # ECS Cluster -> Task Role
        task_role = iam.Role(
            self, 
            id=f'{resource_prefix}-aar-ecs-task-role',
            assumed_by=iam.ServicePrincipal("ecs-tasks"),
            role_name=f'{resource_prefix}-aar-ecs-task-role'
        )

        # ECS Cluster -> Task Role -> Task Role Policy
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

        # ECS Cluster -> Task Definition
        task_definition = ecs.FargateTaskDefinition(
            self,
            id=f'{resource_prefix}-aar-fargate-td',
            memory_limit_mib=4096,
            cpu=2048,
            task_role=task_role,
            execution_role=execution_role,
            family=f'{resource_prefix}-aar-fargate-td'
        )

        # Secrets Manager -> Secret Retrieval
        secrets = {}
        for secret in config['secrets']['variables']:
            secrets[secret] = ecs.Secret.from_secrets_manager(ecs_secrets, secret)
        
        # Log Group Lookup
        log_group = logs.LogGroup(
            self, 
            id=f'{resource_prefix}-aar-ecs-log-group-lookup',
            log_group_name=f'{resource_prefix}-aar-ecs',
            retention=logs.RetentionDays.ONE_MONTH
        )

        # ECS Cluster -> Task Definition -> Container
        container = task_definition.add_container(
            id='hspt-aar-container',
            image=ecs.ContainerImage.from_registry(f'{ecr_repository.repository_uri}:latest'),
            container_name='hspt-aar-container',
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
      
        # Container Port Mappings
        container.add_port_mappings(
            ecs.PortMapping(
                container_port=5000,
                host_port=5000,
                protocol=ecs.Protocol.TCP,
            )
        )

        # ECS Cluster -> Security Group
        ecs_security_group = ec2.SecurityGroup(
            self,
            id=f'{resource_prefix}-aar-fargate-sg',
            vpc=vpc,
            description="Security Group for allawsresources Fargate Cluster",
            security_group_name=f'{resource_prefix}-aar-fargate-sg'
        )

        # ECS Cluster -> Fargate Service
        service = ecs.FargateService(
            self,
            id=f'{resource_prefix}-aar-service',
            cluster=cluster,
            task_definition=task_definition,
            security_groups=[ecs_security_group],
            service_name=f'{resource_prefix}-aar-service',
            desired_count=1,
            enable_execute_command=True,
            assign_public_ip=False
        )

        hosted_zone = r53.HostedZone.from_hosted_zone_attributes(
            self,
            id="hosted-zone-lookup",
            hosted_zone_id=config['route53']['hosted_zone_id'],
            zone_name=config['route53']['hosted_zone_name']
        )
            
        listener_certificate = acm.Certificate(
            self,
            id=f'{resource_prefix}-aar-certificate',
            domain_name=config['route53']['domain'],
            validation=acm.CertificateValidation.from_dns(
                hosted_zone=hosted_zone
            )
        )
        
        load_balancer_security_group = ec2.SecurityGroup(
            self,
            id=f'{resource_prefix}-aar-alb-sg',
            vpc=vpc,
            description="Security Group for allawsresources Fargate Cluster",
            security_group_name=f'{resource_prefix}-aar-alb-sg'
        )

        load_balancer_security_group.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(5000)
        )

        ecs_security_group.add_ingress_rule(
            peer=ec2.Peer.security_group_id(load_balancer_security_group.security_group_id),
            connection=ec2.Port.tcp(5000)
        )

        internal_load_balancer = elbv2.ApplicationLoadBalancer(self, 
            id=f'{resource_prefix}-aar-alb',
            vpc=vpc,
            internet_facing=False,
            vpc_subnets=ec2.SubnetSelection(
                subnet_filters=[
                    ec2.SubnetFilter.by_ids(config['vpc']['subnets'])
                ]
            ),
            load_balancer_name=f'{resource_prefix}-aar-int-alb',
            security_group=load_balancer_security_group
        )

        http_listener = internal_load_balancer.add_listener(
            id=f'{resource_prefix}-aar-alb-80-listener',
            port=80,
            open=True
        )

        http_listener.add_action(f'{resource_prefix}-aar-alb-80-listener-action',
            action=elbv2.ListenerAction.redirect(
            port="443"
        ))

        https_listener = internal_load_balancer.add_listener(
            id=f'{resource_prefix}-aar-alb-443-listener',
            certificates=[listener_certificate],
            port=443,
            open=True
        )

        https_listener.add_action(
            f'{resource_prefix}-aar-alb-443-listener-action',
            action=elbv2.ListenerAction.redirect(
                host=config['route53']['domain']
            )
        )

        target_group = elbv2.ApplicationTargetGroup(
                self,
                id=f'{resource_prefix}-aar-cluster-tg',
                target_group_name=f'{resource_prefix}-aar-cluster-tg',
                target_type=elbv2.TargetType.IP,
                port=5000,
                vpc=vpc,
                protocol=elbv2.ApplicationProtocol.HTTP,
                health_check=elbv2.HealthCheck(
                    enabled=True, path="/", port=str(5000)
                ),
                deregistration_delay=Duration.seconds(0),
            )

        # Add Fargate Instances to Target Group
        target_group.add_target(service)

        # Attach to ALB Listener
        https_listener.add_target_groups(
            id=f'{resource_prefix}-aar-cluster-tg-attachment',
            target_groups=[target_group],
            conditions=[elbv2.ListenerCondition.host_headers([config['route53']['domain']])],
            priority=1,
        )

        # R53 A Record to ALB
        r53.ARecord(
            self,
            id=f'{resource_prefix}-hosted-zone-aar-a-record',
            zone=hosted_zone,
            target=r53.RecordTarget.from_alias(r53targets.LoadBalancerTarget(internal_load_balancer)),
            record_name=config['route53']['domain']
        )