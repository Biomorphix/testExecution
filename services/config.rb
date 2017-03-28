
coreo_uni_util_variables "aws-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.number_violations' => 'unset'}
            ])
end

coreo_uni_util_jsrunner "cloudtrail-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :nothing
end

# cloudtrail end
coreo_uni_util_jsrunner "ec2-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-ec2-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-ec2-rollup" do
  action :nothing
end

# ec2 end
coreo_uni_util_jsrunner "elb-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-elb-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-elb-rollup" do
  action :nothing
end

# elb end
coreo_uni_util_jsrunner "tags-rollup-iam" do
  action :nothing
end
coreo_uni_util_notify "advise-iam-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-iam-rollup" do
  action :nothing
end

#  iam end

coreo_uni_util_jsrunner "tags-rollup-rds" do
  action :nothing
end
coreo_uni_util_notify "advise-rds-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-rds-rollup" do
  action :nothing
end

# rds end
coreo_uni_util_jsrunner "tags-rollup-redshift" do
  action :nothing
end
coreo_uni_util_notify "advise-redshift-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-redshift-rollup" do
  action :nothing
end

# redshift end
coreo_uni_util_notify "advise-s3-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :nothing
end
coreo_uni_util_notify "advise-s3-rollup" do
  action :nothing
end

# s3 end

coreo_uni_util_notify "advise-cloudwatch-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-cloudwatch" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudwatch-rollup" do
  action :nothing
end

# cloudwatch end

coreo_uni_util_notify "advise-kms-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-kms" do
  action :nothing
end
coreo_uni_util_notify "advise-kms-rollup" do
  action :nothing
end

# kms end

coreo_uni_util_notify "advise-sns-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-sns" do
  action :nothing
end
coreo_uni_util_notify "advise-sns-rollup" do
  action :nothing
end

# sns end

coreo_uni_util_jsrunner "splice-violation-object" do
  action :run
  data_type "json"
  json_input '
  {"composite name":"PLAN::stack_name","plan name":"PLAN::name", "services": {
  "cloudtrail": {
   "composite name":"PLAN::stack_name",
   "plan name":"PLAN::name",
   "audit name": "CloudTrail",
   "cloud account name":"PLAN::cloud_account_name",
   "violations": COMPOSITE::coreo_aws_rule_runner_cloudtrail.advise-cloudtrail.report },
  "ec2": {
   "audit name": "EC2",
   "violations": COMPOSITE::coreo_aws_rule_runner_ec2.advise-ec2.report },
  "iam": {
   "audit name": "IAM",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-iam.report },
  "elb": {
   "audit name": "ELB",
   "violations": COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report },
  "rds": {
   "audit name": "RDS",
   "violations": COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report },
  "redshift": {
   "audit name": "REDSHIFT",
   "violations": COMPOSITE::coreo_aws_rule_runner_redshift.advise-redshift.report },
  "s3": {
   "audit name": "S3",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-s3.report },
  "sns": {
     "audit name": "SNS",
     "violations": COMPOSITE::coreo_aws_rule_runner.advise-sns.report },
  "cloudwatch": {
     "audit name": "CLOUDWATCH",
     "violations": COMPOSITE::coreo_aws_rule_runner.advise-cloudwatch.report },
  "kms": {
     "audit name": "KMS",
     "violations": COMPOSITE::coreo_aws_rule_runner.advise-kms.report }
  }}'
  function <<-EOH
  const wayToServices = json_input['services'];
  let newViolation = {};
  let violationCounter = 0;
  const auditStackKeys = Object.keys(wayToServices);
  auditStackKeys.forEach(auditStackKey => {
      let wayForViolation = wayToServices[auditStackKey]['violations'];
      const violationKeys = Object.keys(wayForViolation);
      violationKeys.forEach(violationRegion => {
          if(!newViolation.hasOwnProperty(violationRegion)) {
              newViolation[violationRegion] = {};
          }
          const ruleKeys = Object.keys(wayForViolation[violationRegion]);
          violationCounter+= ruleKeys.length;
          ruleKeys.forEach(objectKey => {
              if(!newViolation[violationRegion].hasOwnProperty(objectKey)) {
                  newViolation[violationRegion][objectKey] = {};
                  newViolation[violationRegion][objectKey]['violations'] = {};
              }
              const objectKeys = Object.keys(wayForViolation[violationRegion][objectKey]['violations']);
              objectKeys.forEach(ruleKey => {
                  newViolation[violationRegion][objectKey]['tags'] = wayForViolation[violationRegion][objectKey]['tags'];
                  newViolation[violationRegion][objectKey]['violations'][ruleKey] = wayForViolation[violationRegion][objectKey]['violations'][ruleKey];
              })
          })
      });
  });
  coreoExport('violationCounter', JSON.stringify(violationCounter));
  callback(newViolation);
  EOH
end

coreo_uni_util_variables "aws-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.splice-violation-object.report'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.splice-violation-object.violationCounter'},

            ])
end


coreo_uni_util_jsrunner "tags-to-notifiers-array-aws" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name":"PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.splice-violation-object.return}'
  function <<-EOH
  

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: " , e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}



function setAlertList() {

  let cloudtrailAlertListToJSON = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
  let redshiftAlertListToJSON = "${AUDIT_AWS_REDSHIFT_ALERT_LIST}";
  let rdsAlertListToJSON = "${AUDIT_AWS_RDS_ALERT_LIST}";
  let iamAlertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
  let elbAlertListToJSON = "${AUDIT_AWS_ELB_ALERT_LIST}";
  let ec2AlertListToJSON = "${AUDIT_AWS_EC2_ALERT_LIST}";
  let s3AlertListToJSON = "${AUDIT_AWS_S3_ALERT_LIST}";
  let cloudwatchAlertListToJSON = "${AUDIT_AWS_CLOUDWATCH_ALERT_LIST}";
  let kmsAlertListToJSON = "${AUDIT_AWS_KMS_ALERT_LIST}";
  let snsAlertListToJSON = "${AUDIT_AWS_SNS_ALERT_LIST}";
  
  
  const alertListMap = new Set();
  
  alertListMap.add(JSON.parse(cloudtrailAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(redshiftAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(rdsAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(iamAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(elbAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(ec2AlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(s3AlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(cloudwatchAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(kmsAlertListToJSON.replace(/'/g, '"')));
  alertListMap.add(JSON.parse(snsAlertListToJSON.replace(/'/g, '"')));
  
  
  let auditAwsAlertList = [];
  
  alertListMap.forEach(alertList => {
      auditAwsAlertList = auditAwsAlertList.concat(alertList);
  });
  
  auditAwsAlertList = JSON.stringify(auditAwsAlertList);

  json_input['alert list'] = auditAwsAlertList || [];
}


function addHeaderForSelfServices(html) {
    let headerHTMLService = `<div style="
        width: 100%;
        background-color: #D3E7E1;
        background-position:0% center;
        background-image:url('http://assets.cloudcoreo.com/wp-content/uploads/2016/11/Moose_FINAL_green_transparent.png');
        background-repeat:no-repeat;
        padding: 40px 0;
        display: flex;
        flex-wrap: wrap;">
    <div style="padding-left: 50%;width:50%;">
        <p style="
            font-size: 24px;
            font-family: 'Arial';
            color:#21896B;">Schedule regular audits <br> and customize your reports.</p>
        <a style="
                margin-top: 3px;
                display: inline-block;
                text-transform: uppercase;
                font-family: 'Arial';
                border-radius:5px;
                color:white;
                background: #3081B7;
                padding: 15px 20px;
                font-size: 16px;
                text-decoration: none;
                font-weight: bold;" href="https://www.cloudcoreo.com/early-access/?utm_source=results&utm_medium=email&utm_campaign=ss-audit">Request an account</a>
    </div>
</div>`;

    

    let indexStart = html.indexOf('<!--ACCOUNT_SUGGESTION_END-->');
    let indexEnd = html.indexOf('<!-- ACCOUNT_SUGGESTION_START -->');
    return html.replace(html.substring(indexStart, indexEnd), headerHTMLService);
}


setTableAndSuppression();
setAlertList();



const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;
const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
     ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditAWS = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);
const newJSONInput = AuditAWS.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJSONInput));
const raw_letters = AuditAWS.getLetters();
const letters = [];

for(var x = 0; x < raw_letters.length; x++){
    //console.log(raw_letters[x]);
    letters.push(JSON.parse(JSON.stringify(raw_letters[x]).replace(/New Owner Tag Report for PLAN::name plan/g,'Detailed Report')));
}

letters.forEach(letter => {
  letter.payload = addHeaderForSelfServices(letter.payload).replace(/PLAN::name/g,'${AUDIT_AWS_ALERT_RECIPIENT}').replace(/Cloud account: \.*/g, '');
});
callback(letters);
  EOH
end


coreo_uni_util_variables "aws-update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.table'}
            ])
end

coreo_uni_util_notify "advise-aws-to-tag-values" do
  action((("${AUDIT_AWS_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.return'
end
