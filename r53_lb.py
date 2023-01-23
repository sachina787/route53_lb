import boto3
import logging
import os
from botocore.config import Config

config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'standard'
   }
)
sts_client = boto3.client('sts')
r53_asume = sts_client.assume_role(
            DurationSeconds=3600,
            RoleArn='arn:aws:iam::***:role/CA_Route53Access',
            RoleSessionName='test_update',
        )

ACCESS_KEY = r53_asume['Credentials']['AccessKeyId']
SECRET_KEY = r53_asume['Credentials']['SecretAccessKey']
SESSION_TOKEN = r53_asume['Credentials']['SessionToken']
logger = logging.getLogger(name=__name__)
env_level = os.environ.get("LOG_LEVEL")
log_level = logging.INFO if not env_level else env_level
logger.setLevel(log_level)
zone_id = os.environ['HostedZoneId']
host_dns = os.environ['HostDns']
asg_name = os.environ['asg_name']
ec2_client = boto3.client("ec2", config=config)
asg_client = boto3.client("autoscaling", config=config)
route53_client = boto3.client("route53", config=config,aws_access_key_id=ACCESS_KEY,aws_secret_access_key=SECRET_KEY,aws_session_token=SESSION_TOKEN,)

def updated_record(TTL,SetIdentifier,HealthCheckId,ResourceRecords,action):
    response = route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': 'Dns to ec2 instance',
                'Changes': [
                    {
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': host_dns,
                            'Type': 'A',
                            'Weight': 10,
                            'SetIdentifier': SetIdentifier,
                            'HealthCheckId': HealthCheckId,
                            'TTL': TTL,
                            'ResourceRecords': ResourceRecords
                        }
                    },
                ]
            }
        )
    return response
    
def Create_healthcheck(referenceId, IP, port, healthcheck_path):
    response = route53_client.create_health_check(
        CallerReference=referenceId,
        HealthCheckConfig={
            'IPAddress': IP,
            'Port': port,
            'Type': 'HTTP',
            'ResourcePath': healthcheck_path,
            'RequestInterval': 10,
            'FailureThreshold': 3,
        }
    )
    return response
        
def lambda_handler(event, context):
    try:
        print(event)
        detail = event['detail']
        instance_id = detail['EC2InstanceId']
        print(instance_id)
        instance_details = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance_ip = instance_details['Reservations'][0]['Instances'][0]['PublicIpAddress']
        set_record = [{'Value':instance_ip}]
        if event["detail-type"] == "EC2 Instance-launch Lifecycle Action" and detail['LifecycleHookName']=="apk-server-asg-launching-lifecyclehook":
            health_check_res = Create_healthcheck(instance_id, instance_ip, <port>, <HEALTH_CHECK_PATH>)
            healthcheck_id = health_check_res['HealthCheck']['Id']
            result = updated_record(1,instance_id,healthcheck_id,set_record,"CREATE")
            print(result)
        elif event["detail-type"] == "EC2 Instance-terminate Lifecycle Action" and detail['LifecycleHookName']=="apk-server-asg-terminating-lifecyclehook":
            healthcheck_id = route53_client.list_resource_record_sets(HostedZoneId=zone_id,StartRecordName=host_dns,StartRecordType='A',StartRecordIdentifier=instance_id)['ResourceRecordSets'][0]['HealthCheckId']
            print(healthcheck_id)
            result = updated_record(1,instance_id,healthcheck_id,set_record,"DELETE")
            print(result)
            res = route53_client.delete_health_check(HealthCheckId=healthcheck_id)
            print(res)
        else:
            logging.error("Lifecycle action didn't matched with the conditions")
    except Exception as e:
        logging.error("Error: %s", str(e))
