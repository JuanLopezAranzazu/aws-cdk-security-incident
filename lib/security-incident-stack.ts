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

    // Resources used to demonstrate least privilege
    const dataBucket = new s3.Bucket(this, "DeveloperDataBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const dataTable = new dynamodb.Table(this, "DeveloperDataTable", {
      partitionKey: {
        name: "id",
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const developerGroup = new iam.Group(this, "RestrictedDevelopersGroup", {
      groupName: "SecurityIncidentRestrictedDevelopers",
    });

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["s3:ListBucket"],
        resources: [dataBucket.bucketArn],
      }),
    );

    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["s3:GetObject", "s3:PutObject"],
        resources: [dataBucket.arnForObjects("*")],
      }),
    );

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
        resources: [dataTable.tableArn],
      }),
    );

    // Explicitly prevent EC2 access even if another policy allows it.
    developerGroup.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        actions: ["ec2:*"],
        resources: ["*"],
      }),
    );

    // Prevent deletion of data in the example resources.
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
        resources: [
          dataBucket.bucketArn,
          dataBucket.arnForObjects("*"),
          dataTable.tableArn,
        ],
      }),
    );

    // CloudTrail: multi-region API auditing
    const trail = new cloudtrail.Trail(this, "SecurityTrail", {
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_WEEK,
      enableFileValidation: true,
    });

    const trailLogGroup = trail.logGroup;

    if (!trailLogGroup) {
      throw new Error("CloudTrail must send events to CloudWatch Logs.");
    }

    // CloudWatch metric filters and security alarms
    const iamChangesFilter = new logs.MetricFilter(
      this,
      "IamChangesMetricFilter",
      {
        logGroup: trailLogGroup,
        metricNamespace: "SecurityIncident",
        metricName: "IAMPolicyChanges",
        metricValue: "1",
        filterPattern: logs.FilterPattern.literal(
          '{ ($.eventSource = "iam.amazonaws.com") && ' +
            '(($.eventName = "PutUserPolicy") || ' +
            '($.eventName = "PutRolePolicy") || ' +
            '($.eventName = "AttachUserPolicy") || ' +
            '($.eventName = "AttachRolePolicy") || ' +
            '($.eventName = "CreatePolicyVersion") || ' +
            '($.eventName = "SetDefaultPolicyVersion")) }',
        ),
      },
    );

    new cloudwatch.Alarm(this, "IamChangesAlarm", {
      alarmName: "SecurityIncident-IAM-Policy-Changes",
      alarmDescription:
        "Detects changes to IAM policies recorded by CloudTrail.",
      metric: iamChangesFilter.metric({
        statistic: "Sum",
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    const ec2ChangesFilter = new logs.MetricFilter(
      this,
      "Ec2ChangesMetricFilter",
      {
        logGroup: trailLogGroup,
        metricNamespace: "SecurityIncident",
        metricName: "EC2InstanceChanges",
        metricValue: "1",
        filterPattern: logs.FilterPattern.literal(
          '{ ($.eventSource = "ec2.amazonaws.com") && ' +
            '(($.eventName = "ModifyInstanceAttribute") || ' +
            '($.eventName = "ModifyInstancesAttribute") || ' +
            '($.eventName = "RunInstances") || ' +
            '($.eventName = "TerminateInstances")) }',
        ),
      },
    );

    new cloudwatch.Alarm(this, "Ec2ChangesAlarm", {
      alarmName: "SecurityIncident-EC2-Changes",
      alarmDescription:
        "Detects selected EC2 instance changes recorded by CloudTrail.",
      metric: ec2ChangesFilter.metric({
        statistic: "Sum",
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // VPC and restricted Security Groups
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

    const applicationSecurityGroup = new ec2.SecurityGroup(
      this,
      "ApplicationSecurityGroup",
      {
        vpc,
        description: "Application traffic only; no public SSH.",
        allowAllOutbound: true,
      },
    );

    const databaseSecurityGroup = new ec2.SecurityGroup(
      this,
      "DatabaseSecurityGroup",
      {
        vpc,
        description: "Database access restricted to the application SG.",
        allowAllOutbound: true,
      },
    );

    // MySQL is only allowed from the application Security Group.
    databaseSecurityGroup.addIngressRule(
      applicationSecurityGroup,
      ec2.Port.tcp(3306),
      "Allow MySQL from the application Security Group only",
    );

    // No inbound rule allows TCP 22 or public TCP 3306.

    // Outputs
    new cdk.CfnOutput(this, "DeveloperGroupName", {
      value: developerGroup.groupName,
    });

    new cdk.CfnOutput(this, "DeveloperDataBucketName", {
      value: dataBucket.bucketName,
    });

    new cdk.CfnOutput(this, "DeveloperDataTableName", {
      value: dataTable.tableName,
    });

    new cdk.CfnOutput(this, "CloudTrailName", {
      value: trail.trailArn,
    });

    new cdk.CfnOutput(this, "CloudTrailLogGroupName", {
      value: trailLogGroup.logGroupName,
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
