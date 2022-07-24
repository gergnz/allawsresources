#!/usr/bin/env python3
import os

import aws_cdk as cdk

from allresources.allresources_stack import AllresourcesStack

app = cdk.App()
AllresourcesStack(app, "AllresourcesStack")

app.synth()
