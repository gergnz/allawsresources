# All AWS Resources

## Deployment...

Todo, finish the CDK

## Application Setup for a new organisation

* A Cross account role with `sts:AssumeRole, organizations:ListAccounts` permission for the source where this app runs.
* Cross account roles that are trusted with ReadOnly permissions for all the accounts in the org.
