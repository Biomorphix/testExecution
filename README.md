audit AWS
============================
This stack will monitor supported AWS services and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor all supported AWS services against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_HTML_REPORT`:
  * description: Would you like to send the AWS owner tag report(s)? Options - notify / nothing. Default is nothing.
  * default: nothing

### `AUDIT_AWS_ROLLUP_REPORT`:
  * description: Would you like to send a Summary AWS report? Options - notify / nothing. Default is nothing.
  * default: nothing

### `AUDIT_AWS_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the AWS services being audited. (Optional)
  * default: NOT_A_TAG

### `AUDIT_AWS_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_CLOUDTRAIL_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all Cloudtrail alerts. Possible values are cloudtrail-inventory,cloudtrail-service-disabled,cloudtrail-log-file-validating,cloudtrail-logs-cloudwatch,cloudtrail-no-global-trails
  * default: cloudtrail-service-disabled, cloudtrail-log-file-validating, cloudtrail-logs-cloudwatch, cloudtrail-no-global-trails

### `AUDIT_AWS_REDSHIFT_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all Redshift alerts. Choices are redshift-publicly-accessible,redshift-encrypted,redshift-no-version-upgrade,redshift-no-require-ssl,redshift-no-s3-logging,redshift-no-user-logging,redshift-snapshot-retention,redshift-inventory
  * default: redshift-publicly-accessible, redshift-encrypted, redshift-no-version-upgrade, redshift-no-require-ssl, redshift-no-s3-logging, redshift-no-user-logging, redshift-snapshot-retention

### `AUDIT_AWS_RDS_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all RDS alerts. Choices are rds-short-backup-retention-period,rds-no-auto-minor-version-upgrade,rds-db-publicly-accessible,rds-inventory
  * default: rds-short-backup-retention-period, rds-no-auto-minor-version-upgrade, rds-db-publicly-accessible

### `AUDIT_AWS_IAM_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all IAM alerts.
  * default: iam-unusediamgroup, iam-inactive-key-no-rotation, iam-active-key-no-rotation, iam-passwordreuseprevention, iam-missing-password-policy, iam-expirepasswords, iam-no-mfa, iam-root-no-mfa, iam-root-active-key, iam-root-active-password, iam-user-attached-policies, iam-password-policy-uppercase, iam-password-policy-lowercase, iam-password-policy-symbol, iam-password-policy-number, iam-password-policy-min-length, iam-root-access-key-1, iam-root-access-key-2, iam-inventory-users, iam-inventory-roles, iam-inventory-groups, iam-inventory-policies

### `AUDIT_AWS_ELB_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all ELB alerts. Choices are elb-old-ssl-policy,elb-current-ssl-policy,elb-inventory
  * default: elb-old-ssl-policy

### `AUDIT_AWS_EC2_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all EC2 alerts. Choices are ec2-inventory-instances,ec2-inventory-security-groups,ec2-ip-address-whitelisted,ec2-unrestricted-traffic,ec2-TCP-1521-0.0.0.0/0,ec2-TCP-3306-0.0.0.0/0,ec2-TCP-5432-0.0.0.0/0,ec2-TCP-27017-0.0.0.0/0,ec2-TCP-1433-0.0.0.0/0,ec2-TCP-3389-0.0.0.0/0,ec2-TCP-22-0.0.0.0/0,ec2-TCP-5439-0.0.0.0/0,ec2-TCP-23,ec2-TCP-21,ec2-TCP-20,ec2-ports-range,ec2-not-used-security-groups
  * default: ec2-ip-address-whitelisted, ec2-unrestricted-traffic, ec2-TCP-1521-0.0.0.0/0, ec2-TCP-3306-0.0.0.0/0, ec2-TCP-5432-0.0.0.0/0, ec2-TCP-27017-0.0.0.0/0, ec2-TCP-1433-0.0.0.0/0, ec2-TCP-3389-0.0.0.0/0, ec2-TCP-22-0.0.0.0/0, ec2-TCP-5439-0.0.0.0/0, ec2-TCP-23, ec2-TCP-21, ec2-TCP-20, ec2-ports-range, ec2-not-used-security-groups

### `AUDIT_AWS_S3_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all S3 alerts. Choices are s3-allusers-write,s3-allusers-write-acp,s3-allusers-read,s3-authenticatedusers-write,s3-authenticatedusers-write-acp,s3-authenticatedusers-read,s3-logging-disabled,s3-world-open-policy-delete,s3-world-open-policy-get,s3-world-open-policy-list,s3-world-open-policy-put,s3-world-open-policy-all,s3-only-ip-based-policy
  * default: s3-allusers-write, s3-allusers-write-acp, s3-allusers-read, s3-authenticatedusers-write, s3-authenticatedusers-write-acp, s3-authenticatedusers-read, s3-logging-disabled, s3-world-open-policy-delete, s3-world-open-policy-get, s3-world-open-policy-list, s3-world-open-policy-put, s3-world-open-policy-all, s3-only-ip-based-policy

### `AUDIT_AWS_CLOUDWATCH_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all Cloudwatch alerts. Choices are cloudwatch-inventory
  * default: cloudwatch-inventory

### `AUDIT_AWS_KMS_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all KMS alerts. Choices are kms--inventory
  * default: kms-inventory

### `AUDIT_AWS_SNS_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all SNS alerts. Choices are sns-inventory
  * default: sns-inventory


## Optional variables with no default

### `AUDIT_AWS_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. AWS


## Categories
1. Audit


## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws/master/images/icon.png "icon")

