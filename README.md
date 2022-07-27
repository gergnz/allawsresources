# All AWS Resources

## Deployment...

1. Update cdk.json and create an alias for your account, eg 'dev'
2. Fill out the required fields, such as:
```
"accounts": {
      "dev": {
        "account_id": "",
        "resource_prefix": "dev",
        "vpc": {
          "vpc_id_ssm": "/application/vpc",
          "subnets": ["subnet-a", "subnet-b", "subnet-c"]
        },
        "ecr": {
          "repository_name": "aar-ecr"
        },
        "secrets": {
          "variables": ["SECRET_KEY"]
        },
        "route53": {
          "hosted_zone_id": "XYZ",
          "hosted_zone_name": "example.com",
          "domain": "aar.example.com"
        }
      }
    }
```
* domain: The FQDN of the domain that will be used in ALB rules and added to your Hosted Zone
* vpc_id_ssm: Store the VPC you will use in an SSM parameter

3. Run a synth using the following format:
```
cdk synth -c account_name='dev'
```

## Application Setup for a new organisation

* A Cross account role with `sts:AssumeRole, organizations:ListAccounts` permission for the source where this app runs.
* Cross account roles that are trusted with ReadOnly permissions for all the accounts in the org.
