# AWS-Config-Rules

AWS Config Rules Hands-on
The The target of
Custom rules for AWS Config Rules are made by creating Lambda.  By actually experiencing custom rule creation, you will be more likely to develop future Config Rule.  
Teaching materials

Use awslabs aws-config-rules.
Cases
In this section, you will create the following rules inLambda(Python):）Create the following rules in (
•	Security group inspection with Out inbound rules of 0.0.0.0
•	Checking Out for iam users that are not actually being used
How it works
As written in the documentation,AWSConfig Rules has two trigger types: In this example, both use Detect on Change. In the case of Detect on Change, the resource information is passed as an event to the lambda variable, unless the target resource is zero. You can also evaluate all resources by "reevaluation". In the case of "periodic execution", resource information is not passed, so it is necessary to extract the resource information itself in code.  
AWS Config Set up
By default, global resources such as IAM are not covered and are not evaluated when you create rules. In AWSConfig Settings, select the check box to include global resources (suchasAWS IAM resources).   
Sos
Source Entry
Create a working directory and clone I will from GitHub.  
$ mkdir Config
$ cd Config/
$ git clone https://github.com/awslabs/aws-config-rules.git
Cloning into 'aws-config-rules'...
remote: Counting objects: 575, done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 575 (delta 2), reused 3 (delta 0), pack-reused 565
Receiving objects: 100% (575/575), 157.63 KiB | 140.00 KiB/s, done.
Resolving deltas: 100% (331/331), done.
$ 
Structure of the event to be passed
An example of an event in an AWS Config rule is helpful. However, since not all event specifications are listed, it is recommended that you output configurationItem for each resource and check the contents.  
We're dealing with EC2 and IAM users. Here is an example of an invitationEvent for these resources: Note that configurationItem itself does not exist for calls withScheduledEvent or if the called does not have a resource to evaluate.  
EC2
{
    "recordVersion": "1.3",
    "configurationItem": {
        "relationships": [],
"configurationItemCaptureTime": "2018-07-04T01:54:02.810Z",
        "availabilityZone": null,
        "configurationStateMd5Hash": "",
        "tags": {},
        "resourceType": "AWS::EC2::Instance",
        "configurationItemVersion": "1.3",
        "configurationStateId": 1530669242810,
        "relatedEvents": [],
        "awsRegion": "ap-northeast-1",
"ARN": "arn:aws:ec2:ap-northeast-1:xxxxxxxxxxxxxxxxxx:instance/i-05888074e384774ef,"
        "supplementaryConfiguration": {},
        "resourceName": null,
        "configuration": null,
        "resourceId": "i-05888074e384774ef",
        "resourceCreationTime": null,
        "configurationItemStatus": "ResourceDeleted",
        "awsAccountId": "xxxxxxxxxxxxxxx"
    },
"notificationCreationTime": "2018-07-05T14:40:13.752Z",
"messageType": "ConfigurationItemChangeNotification",
    "configurationItemDiff": null
}
IAM Users ー
{
    "recordVersion": "1.3",
    "configurationItem": {
        "relationships": [
            {
                "resourceType": "AWS::IAM::Policy",
                "resourceId": "ANPAJUAZCQRMVSYFQNJPI",
                "name": "Is attached to CustomerManagedPolicy",
                "resourceName": "trainexpenser-codecommit-readonly"
            }
        ],
"configurationItemCaptureTime": "2018-07-05T15:22:21.203Z",
        "availabilityZone": "Not Applicable",
        "configurationStateMd5Hash": "",
        "tags": {},
        "resourceType": "AWS::IAM::User",
        "configurationItemVersion": "1.3",
        "configurationStateId": 1530804141203,
        "relatedEvents": [],
        "awsRegion": "global",
        "ARN": "arn:aws:iam::xxxxxxxxxxxx:user/trainexpenser-codecommit-readonly",
        "supplementaryConfiguration": {},
        "resourceName": "trainexpenser-codecommit-readonly",
        "configuration": {
            "userName": "trainexpenser-codecommit-readonly",
            "groupList": [],
"createDate": "2017-12-01T05:01:21.000Z",
            "userId": "AIDAIKBNZFI2LJRYEOI3G",
            "userPolicyList": null,
            "path": "/",
            "attachedManagedPolicies": [
                {
                    "policyName": "trainexpenser-codecommit-readonly",
                    "policyArn": "arn:aws:iam::xxxxxxxxxxxxx:policy/trainexpenser-codecommit-readonly"
                }
            ],
            "arn": "arn:aws:iam::xxxxxxxxxxxxx:user/trainexpenser-codecommit-readonly"
        },
        "resourceId": "AIDAIKBNZFI2LJRYEOI3G",
"resourceCreationTime": "2017-12-01T05:01:21.000Z",
        "configurationItemStatus": "ResourceDiscovered",
        "awsAccountId": "xxxxxxxxxxxx"
    },
"notificationCreationTime": "2018-07-05T15:22:49.724Z",
"messageType": "ConfigurationItemChangeNotification",
    "configurationItemDiff": null
}
Security group inspection, including inbound Out0.0.0/0
This rule is already provided in the sample(ec2-exposed-instance.py). The following Sourcesources are described.  
#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no EC2 instances allow public access to the specified ports.
# Description: Checks that all instances block access to the specified ports.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Accepted Parameters: examplePort1, exampleRange1, examplePort2, ...
# Example Values: 8080, 1-1024, 2375, ...


import json
import boto3

# An array of resources to which the rule applies. Used in evaluate_compliance().  
APPLICABLE_RESOURCES = ["AWS::EC2::Instance"]

# Converts the hidden port number definition (forbidden ports) を to range.   1 If it is one, it is only that port. 
def expand_range(ports):
    if "-" in ports:
        return range(int(ports.split("-")[0]), int(ports.split("-")[1])+1)
    else:
        return [int(ports)]

Locate and collect the IpRanges setting that contains # 0.0.0.0/0.  
def find_exposed_ports(ip_permissions):
    exposed_ports = []
    for permission in ip_permissions:
        if next((r for r in permission["IpRanges"]
                if "0.0.0.0/0" in r["CidrIp"]), None):
                    exposed_ports.extend(range(permission["FromPort"],
                                               permission["ToPort"]+1))
    return exposed_ports

# exporsed_ports returns arule violation ifforbidden_ports is included.  1 The discovery ends when the first one is found. 
# exporsed_ports * forbidden_ports   is calculated. 
# forbidden_portsの例: {"examplePort1":"8080", "exampleRange1":"1-1024", "examplePort2":"2375"}
def find_violation(ip_permissions, forbidden_ports):
    exposed_ports = find_exposed_ports(ip_permissions)
    for forbidden in forbidden_ports:
        ports = expand_range(forbidden_ports[forbidden])
        for port in ports:
            if port in exposed_ports:
                return "A forbidden port is exposed to the internet."

    return None


# This is the main function of the evaluation. 
def evaluate_compliance(configuration_item, rule_parameters):
# Returns as NOT_APPLICABLE if it is not the target resource type. 
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

# Returns as NOT_APPLICABLE if the resource has already been deleted.  
    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated"
        }

    security_groups = configuration_item["configuration"].get("securityGroups")

# Returns as NON_COMPLIANT if the security group is not attached in the first place. 
    if security_groups is None:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": "The instance doesn't pertain to any security groups."
        }

    ec2 = boto3.resource("ec2")
# Inspect all security groups. 
    for security_group in security_groups:
# Retrieves IP permissions. 
        ip_permissions = ec2. SecurityGroup(
                                           security_group["groupId"]
                                          ).ip_permissions
# Check for violations. 
        violation = find_violation(
            ip_permissions,
            rule_parameters
        )

# If anything other than None is returned, it returns NON_COMPLIANT and its contents as violations. 
        if violation:
            return {
                "compliance_type": "NON_COMPLIANT",
                "annotation": violation
            }

# Returns APPLY because the check passed. 
    return {
        "compliance_type": "COMPLIANT",
        "annotation": "This resource is compliant with the rule."
    }


# Lambda's main function. Called for each resource to be checked. 
# Use the following three of the events: 
# invokeevent/configurationItem: Resource settings
# ruleParameters: Array of rule parameters  -> (key, value) Array ofin AWS Config Rules
# resultToken: Token to use when putting the result into AWS  To Config Tokens to use when
def lambda_handler(event, context):

# Each data / parameter / token retrieve
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = json.loads(event["ruleParameters"])

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

# Rating
    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    # boto3UsingAWS Config the result toput
    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
# Typically use input resource type/resource ResourceID Resource types in
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                    
# The following two are the results of the evaluation
                # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE
                "ComplianceType":
                    evaluation["compliance_type"],
# Result string
                "Annotation":
                    evaluation["annotation"],
                  
# Time stamp used for sorting
# You can use the time stamp at the time of capture
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
Checking Outfor iam users that are not actually being used
This rule is also provided in the sample(iam-inactive-user.py). The following Source sources are described. The parts that overlap with the previous section are omitted.  
#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have been inactive for a period longer than specified.
# Description: Checks that all users have been active for earlier than specified.
#
# Trigger Type: Change Triggered
# Scope of Changes: IAM:User
# Required Parameters: maxInactiveDays
# Example Value: 90


import json
import boto3
import datetime


APPLICABLE_RESOURCES = ["AWS::IAM::User"]

# Calculates the number of days of the given date and the current difference
def calculate_age(date):
    now = datetime.datetime.utcnow().date()
    then = date.date()
    age = now - then

    return age.days


def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return "NOT_APPLICABLE"

    config = boto3.client("config")
# There may be changes from the event being given, so just in case, retrieve the username with the resource ID as the key from the latest information in AWS Config  Retrieve the user name with the resource ID as the key from the latest information on
    resource_information = config.get_resource_config_history(
        resourceType=configuration_item["resourceType"],
        resourceId=configuration_item["resourceId"]
    )
    user_name = resource_information["configurationItems"][0]["resourceName"]

# Use the IAM API to retrieve passwordLastUsed for the IAM user
    iam = boto3.client("iam")
    user = iam.get_user(UserName=user_name)
    last_used = user["User"].get("PasswordLastUsed")
    
# Retrieves unused period thresholds from parameters
    max_inactive_days = int(rule_parameters["maxInactiveDays"])

# Returns as NON_COMPIANT if the unused period exceeds the threshold specified by  NON_COMPIANT  the parameter
    if last_used is not None and calculate_age(last_used) > max_inactive_days:
        return "NON_COMPLIANT"

    return "COMPLIANT"


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = json.loads(event["ruleParameters"])

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                "ComplianceType":
                    evaluate_compliance(configuration_item, rule_parameters),
                "Annotation":
                    "The user has never logged in.", # COMPIANTThe same is true forAnnotation It has become
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
The creation of lambda variables
The Lambda function for AWS Config Rules consists of the following:  
•	A row for lambda functions that have access to AWS Config Rules
•	Source code package(zip)）
Create roles for custom rules for AWS Config rules
The first step is to create a role. You 1 can create a role and reuse it for multiple rules. This role is a service role for Lambda variables and requires permissions to CloudWatch Logs and access to AWSConfig for  logging. Create it as follows:  
1.	Create the policy file required to create the service role for the Lamdda function. 
lambda-exec-role-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
     {
       "Action": "sts:AssumeRole",
       "Principal": {
         "Service": "lambda.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
     }
  ]
}
2.	Create a role with the create-role API. The role name is lambda-config-rules-role.  After creation, get the ARN.   You can always get it by running get-role.  
$ ls
aws-config-rules		lambda-exec-role-policy.json
* Directory wheregit clone was run
$ aws iam create-role --role-name lambda-config-rules-role --assume-role-policy-document file://lambda-exec-role-policy.json
{
    "Role": {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17", 
            "Statement": [
                {
                    "Action": "sts:AssumeRole", 
                    "Sid": "", 
                    "Effect": "Allow", 
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    }
                }
            ]
        }, 
        "RoleId": "AROAJSIB5RAT7Y2JOAEUA", 
"CreateDate": "2018-07-05T12:38:22.114Z",
        "RoleName": "lambda-config-rules-role", 
        "Path": "/", 
"Arn": "arn:aws:iam:::xxxxxxxxxxxxxxxs:role/lambda-config-rules-role"
    }
}

$ aws iam get-role --role-name lambda-config-rules-role
* Same results are returned aswhen create-role was made.
3.	Add the required policies for the role. Using existing policies,cloudWatchLogsFullAccess and AWSConfigRulesExecutionRole. as now In the 
$ aws iam attach-role-policy --role-name lambda-config-rules-role --policy-arn "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
$ aws iam attach-role-policy --role-name lambda-config-rules-role --policy-arn "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
$ aws iam attach-role-policy --role-name lambda-config-rules-role --policy-arn "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
$ aws iam attach-role-policy --role-name lambda-config-rules-role --policy-arn "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
$ aws iam list-attached-role-policies --role-name lambda-config-rules-role
{
    "AttachedPolicies": [
        {
            "PolicyName": "AmazonEC2ReadOnlyAccess", 
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
        }, 
        {
            "PolicyName": "CloudWatchLogsFullAccess", 
            "PolicyArn": "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
        }, 
        {
            "PolicyName": "IAMReadOnlyAccess", 
            "PolicyArn": "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
        }, 
        {
            "PolicyName": "AWSConfigRulesExecutionRole", 
            "PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
        }
    ]
}
Lambda function Yes
Zip the source code and create a function with the role in the previous section.  
1.	Create a Zip file. 
$ zip -j ec2-exposed-instance.zip aws-config-rules/python/ec2-exposed-instance.py 
  adding: ec2-exposed-instance.py (deflated 68%)
$ zip -j iam-inactive-user.zip aws-config-rules/python/iam-inactive-user.py
  adding: iam-inactive-user.py (deflated 61%) 
2.	Create a lambda variable. Change the ARN of the role to the actual one.  
$ aws lambda create-function \
 --function-name awsconfig-ec2-exposed-instance \
 --runtime python2.7 \
--role arn:aws:iam:::xxxxxxxxxxxs:role/lambda-config-rules-role
 --handler ec2-exposed-instance.lambda_handler \
 --timeout 300 \
 --zip-file fileb://ec2-exposed-instance.zip
{
    "TracingConfig": {
        "Mode": "PassThrough"
    }, 
    "CodeSha256": "f+ZThR3wLwsK9AHcupb7MNFLtKl3H5tnAxA77vg2ILo=", 
    "FunctionName": "awsconfig-ec2-exposed-instance", 
    "CodeSize": 1473, 
    "RevisionId": "ba1b0512-2646-4571-92e3-728fe627d8a3", 
    "MemorySize": 128, 
    "FunctionArn": "arn:aws:lambda:ap-northeast-1:xxxxxxxxxxxxx:function:awsconfig-ec2-exposed-instance", 
    "Version": "$LATEST", 
    "Role": "arn:aws:iam::xxxxxxxxxxxxxxx:role/lambda-config-rules-role", 
    "Timeout": 300, 
    "LastModified": "2018-07-05T13:18:28.119+0000", 
    "Handler": "lambda_handler", 
    "Runtime": "python2.7", 
    "Description": ""
}
$ aws lambda create-function \
 --function-name awsconfig-iam-inactive-user \
 --runtime python2.7 \
--role arn:aws:iam:::xxxxxxxxxxxs:role/lambda-config-rules-role
 --handler iam-inactive-user.lambda_handler \
 --timeout 300 \
 --zip-file fileb://iam-inactive-user.zip
{
    "TracingConfig": {
        "Mode": "PassThrough"
    }, 
    "CodeSha256": "yRuXariCEPmjSqZ0GKOHcVhzk2/1B14+C+9BpMQzkXs=", 
    "FunctionName": "awsconfig-iam-inactive-user", 
    "CodeSize": 1115, 
    "RevisionId": "ba7be6ef-5148-4790-80c2-73f232e5536d", 
    "MemorySize": 128, 
    "FunctionArn": "arn:aws:lambda:ap-northeast-1:xxxxxxxxxxxx:function:awsconfig-iam-inactive-user", 
    "Version": "$LATEST", 
    "Role": "arn:aws:iam::xxxxxxxxxxxx:role/lambda-config-rules-role", 
    "Timeout": 300, 
    "LastModified": "2018-07-05T13:19:29.453+0000", 
    "Handler": "lambda_handler", 
    "Runtime": "python2.7", 
    "Description": ""
}
3.	Receive From lambda triggers from AWS Config and grant permission. Change the source-account to your account number.  
$ aws lambda add-permission \
> --function-name awsconfig-ec2-exposed-instance \
> --statement-id 1 \
> --principal config.amazonaws.com \
> --action lambda:InvokeFunction \
--source-account xxxxxxxxxxxxxxxxxxx
{
    "Statement": "{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:xxxxxxxxxxxxx:function:awsconfig-ec2-exposed-instance\",\"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"xxxxxxxxxxxxx\"}}}"
} 
$ aws lambda add-permission \
> --function-name awsconfig-iam-inactive-user \
> --statement-id 1 \
> --principal config.amazonaws.com \
> --action lambda:InvokeFunction \
> --source-account xxxxxxxxxx
{
    "Statement": "{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:xxxxxxxxxxxxxxx:function:awsconfig-iam-inactive-user\",\"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"xxxxxxxxxxxxx\"}}}"
}
$ 
AWS Config Create a rule
Create a json file for the rule definition and use it to create the rule.  SourceIdentifier.   Specify the ARN of the actual Lambda variable.  
ec2-exposed-instance-rule.json
{
	"ConfigRuleName": "EC2-Exposed-Instance",
	"Description": "Evaluates EC2 instances which expose port(s).",
	"Scope": {
		"ComplianceResourceTypes": [
			"AWS::EC2::Instance"
		]
	},
	"Source": {
		"Owner": "CUSTOM_LAMBDA",
		"SourceIdentifier": "arn:aws:lambda:ap-northeast-1:xxxxxxxxxx:function:awsconfig-ec2-exposed-instance",
		"SourceDetails": [{
			"EventSource": "aws.config",
			"MessageType": "ConfigurationItemChangeNotification"
		}]
	},
	"InputParameters": "{\"examplePort1\":\"8080\", \"exampleRange1\":\"1-1024\", \"examplePort2\":\"2375\"}"
}
iam-inactive-user-rule.json
{
	"ConfigRuleName": "IAM-Inactive-Users",
	"Description": "Evaluates inactive IAM users.",
	"Scope": {
		"ComplianceResourceTypes": [
			"AWS::IAM::User"
		]
	},
	"Source": {
		"Owner": "CUSTOM_LAMBDA",
		"SourceIdentifier": "arn:aws:lambda:ap-northeast-1:xxxxxxxxxxx:function:awsconfig-iam-inactive-user",
		"SourceDetails": [{
			"EventSource": "aws.config",
			"MessageType": "ConfigurationItemChangeNotification"
		}]
	},
	"InputParameters": "{\"maxInactiveDays\":\"90\"}"
}
$ aws configservice put-config-rule --config-rule file://ec2-exposed-instance-rule.json 
$ aws configservice put-config-rule --config-rule file://iam-inactive-user-rule.json 
At thisAWS Config point, you  can perform an assessment of all resources by pressing Reevaluation from the AWS Config console. 

