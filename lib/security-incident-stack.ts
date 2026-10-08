import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as iam from "aws-cdk-lib/aws-iam";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as cloudtrail from "aws-cdk-lib/aws-cloudtrail";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as logs from "aws-cdk-lib/aws-logs";

export class SecurityIncidentStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create example resources to demonstrate least-privilege access.
    const developerBucket = new s3.Bucket(this, "DeveloperDataBucket", {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const developerTable = new dynamodb.Table(this, "DeveloperDataTable", {
      partitionKey: {
        name: "id",
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Create a restricted developer group.
    const developerGroup = new iam.Group(this, "RestrictedDevelopersGroup", {
      groupName: "SecurityIncidentRestrictedDevelopers",
    });

    // Allow listing the bucket and reading or uploading objects without deleting them.
    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["s3:ListBucket"],
        resources: [developerBucket.bucketArn],
      }),
    );

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["s3:GetObject", "s3:PutObject"],
        resources: [developerBucket.arnForObjects("*")],
      }),
    );

    // Allow read-only operations on the example DynamoDB table.
    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "dynamodb:GetItem",
          "dynamodb:BatchGetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:DescribeTable",
        ],
        resources: [developerTable.tableArn],
      }),
    );

    // Explicitly deny EC2 actions for members of this group.
    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        actions: ["ec2:*"],
        resources: ["*"],
      }),
    );

    // Prevent deletion of objects, buckets, table items, and tables.
    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        actions: [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:DeleteBucket",
          "dynamodb:DeleteItem",
          "dynamodb:DeleteTable",
        ],
        resources: ["*"],
      }),
    );

    // Enable multi-region CloudTrail auditing and send events to CloudWatch Logs.
    const trail = new cloudtrail.Trail(this, "SecurityTrail", {
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_WEEK,
      enableFileValidation: true,
    });

    const cloudTrailLogGroup = trail.logGroup;

    if (!cloudTrailLogGroup) {
      throw new Error("CloudTrail log group was not created.");
    }

    // Detect IAM policy changes, including changes to group policies.
    const iamPolicyChanges = new logs.MetricFilter(
      this,
      "IamChangesMetricFilter",
      {
        logGroup: cloudTrailLogGroup,
        metricNamespace: "SecurityIncident",
        metricName: "IAMPolicyChanges",
        filterPattern: logs.FilterPattern.literal(
          '{ ($.eventSource = "iam.amazonaws.com") && ' +
            '($.eventName = "PutUserPolicy" || ' +
            '$.eventName = "PutRolePolicy" || ' +
            '$.eventName = "PutGroupPolicy" || ' +
            '$.eventName = "AttachUserPolicy" || ' +
            '$.eventName = "AttachRolePolicy" || ' +
            '$.eventName = "AttachGroupPolicy" || ' +
            '$.eventName = "CreatePolicyVersion" || ' +
            '$.eventName = "SetDefaultPolicyVersion") }',
        ),
        metricValue: "1",
      },
    );

    const iamPolicyChangesAlarm = new cloudwatch.Alarm(
      this,
      "IamChangesAlarm",
      {
        alarmName: "SecurityIncident-IAM-Policy-Changes",
        alarmDescription:
          "Detects changes to IAM policies recorded by CloudTrail.",
        metric: iamPolicyChanges.metric({
          statistic: "Sum",
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );

    // Detect selected EC2 instance changes.
    const ec2InstanceChanges = new logs.MetricFilter(
      this,
      "Ec2ChangesMetricFilter",
      {
        logGroup: cloudTrailLogGroup,
        metricNamespace: "SecurityIncident",
        metricName: "EC2InstanceChanges",
        filterPattern: logs.FilterPattern.literal(
          '{ ($.eventSource = "ec2.amazonaws.com") && ' +
            '($.eventName = "ModifyInstanceAttribute" || ' +
            '$.eventName = "ModifyInstancesAttribute" || ' +
            '$.eventName = "RunInstances" || ' +
            '$.eventName = "TerminateInstances") }',
        ),
        metricValue: "1",
      },
    );

    const ec2InstanceChangesAlarm = new cloudwatch.Alarm(
      this,
      "Ec2ChangesAlarm",
      {
        alarmName: "SecurityIncident-EC2-Changes",
        alarmDescription:
          "Detects selected EC2 instance changes recorded by CloudTrail.",
        metric: ec2InstanceChanges.metric({
          statistic: "Sum",
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );

    // Detect changes to Security Group ingress and egress rules.
    const securityGroupChanges = new logs.MetricFilter(
      this,
      "SecurityGroupChangesFilter",
      {
        logGroup: cloudTrailLogGroup,
        metricNamespace: "SecurityIncident",
        metricName: "SecurityGroupChanges",
        filterPattern: logs.FilterPattern.literal(
          '{ ($.eventSource = "ec2.amazonaws.com") && ' +
            '($.eventName = "AuthorizeSecurityGroupIngress" || ' +
            '$.eventName = "RevokeSecurityGroupIngress" || ' +
            '$.eventName = "AuthorizeSecurityGroupEgress" || ' +
            '$.eventName = "RevokeSecurityGroupEgress" || ' +
            '$.eventName = "ModifySecurityGroupRules" || ' +
            '$.eventName = "UpdateSecurityGroupRuleDescriptionsIngress" || ' +
            '$.eventName = "UpdateSecurityGroupRuleDescriptionsEgress") }',
        ),
        metricValue: "1",
      },
    );

    const securityGroupChangesAlarm = new cloudwatch.Alarm(
      this,
      "SecurityGroupChangesAlarm",
      {
        alarmName: "SecurityIncident-SecurityGroup-Changes",
        alarmDescription:
          "Detects Security Group rule changes recorded by CloudTrail.",
        metric: securityGroupChanges.metric({
          statistic: "Sum",
          period: cdk.Duration.minutes(5),
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      },
    );

    // Create a VPC without NAT Gateways to avoid unnecessary costs.
    const vpc = new ec2.Vpc(this, "SecurityVpc", {
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        {
          name: "public",
          subnetType: ec2.SubnetType.PUBLIC,
        },
      ],
    });

    // Create an application Security Group with no public inbound access.
    const applicationSecurityGroup = new ec2.SecurityGroup(
      this,
      "ApplicationSecurityGroup",
      {
        vpc,
        description: "Application traffic only; no public SSH.",
        allowAllOutbound: true,
      },
    );

    // Create a database Security Group with MySQL access restricted to the application SG.
    const databaseSecurityGroup = new ec2.SecurityGroup(
      this,
      "DatabaseSecurityGroup",
      {
        vpc,
        description: "Database access restricted to the application SG.",
        allowAllOutbound: true,
      },
    );

    // Allow MySQL only from the application Security Group.
    databaseSecurityGroup.addIngressRule(
      applicationSecurityGroup,
      ec2.Port.tcp(3306),
      "Allow MySQL from the application Security Group only",
    );

    new cdk.CfnOutput(this, "DeveloperGroupName", {
      value: developerGroup.groupName,
    });

    new cdk.CfnOutput(this, "DeveloperDataBucketName", {
      value: developerBucket.bucketName,
    });

    new cdk.CfnOutput(this, "DeveloperDataTableName", {
      value: developerTable.tableName,
    });

    new cdk.CfnOutput(this, "CloudTrailName", {
      value: trail.trailArn,
    });

    new cdk.CfnOutput(this, "CloudTrailLogGroupName", {
      value: cloudTrailLogGroup.logGroupName,
    });

    new cdk.CfnOutput(this, "IamPolicyChangesAlarmName", {
      value: iamPolicyChangesAlarm.alarmName,
    });

    new cdk.CfnOutput(this, "Ec2InstanceChangesAlarmName", {
      value: ec2InstanceChangesAlarm.alarmName,
    });

    new cdk.CfnOutput(this, "SecurityGroupChangesAlarmName", {
      value: securityGroupChangesAlarm.alarmName,
    });

    new cdk.CfnOutput(this, "VpcId", {
      value: vpc.vpcId,
    });

    new cdk.CfnOutput(this, "ApplicationSecurityGroupId", {
      value: applicationSecurityGroup.securityGroupId,
    });

    new cdk.CfnOutput(this, "DatabaseSecurityGroupId", {
      value: databaseSecurityGroup.securityGroupId,
    });
  }
}
