#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { SecurityIncidentStack } from "../lib/security-incident-stack";

const app = new cdk.App();

new SecurityIncidentStack(app, "SecurityIncidentStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: "us-east-1",
  },
});
