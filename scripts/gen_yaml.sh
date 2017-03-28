#!/bin/bash

export SERVICES="
stack-audit-aws-cloudtrail
stack-audit-aws-cloudwatch
stack-audit-aws-ec2
stack-audit-aws-elb
stack-audit-aws-iam
stack-audit-aws-kms
stack-audit-aws-rds
stack-audit-aws-redshift
stack-audit-aws-s3
stack-audit-aws-sns
"

export YAMLS="
config
table
suppression
"

set -x

rm -f table.yaml
rm -f suppression.yaml
touch table.yaml
touch suppression.yaml

for f in $SERVICES
do
  for y in $YAMLS
  do
  	echo "puts YAML.dump(YAML.load_file(\"../${f}/extends/${y}.yaml\"));" > foo
    ruby -ryaml foo > out.yaml
    rm -f foo
    YAML_CHECK_STATUS=$?
    echo "YAML_CHECK_STATUS: $YAML_CHECK_STATUS"
    if [ $YAML_CHECK_STATUS -eq 1 ]
    then
      echo "YAML ERROR: ../$f/$y. Exiting."
      exit 1
    else
      if [ "$y" == "table" ]
      then
        cat out.yaml >> table.yaml
      fi
      if [ "$y" == "suppression" ]
      then
        cat out.yaml >> suppression.yaml
      fi
      rm -f out.yaml
    fi
  done
done


