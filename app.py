#!/usr/bin/env python3
import os
import aws_cdk as cdk

from allresources.allresources_stack import AllresourcesStack

app = cdk.App()

account = app.node.try_get_context('account_name')
config = app.node.try_get_context('accounts')[account]

env = cdk.Environment(
    account=config['account_id'],
    region="ap-southeast-2"
)

resource_prefix = config['resource_prefix']

AllresourcesStack(app, f'{resource_prefix}-aar-stack', stack_name=f'{resource_prefix}-aar-stack', env=env, config=config, synthesizer=cdk.DefaultStackSynthesizer(generate_bootstrap_version_rule=False))

app.synth()
