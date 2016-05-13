## 
## autoremediate-EC2-004.py: Lambda function to automatically remediate Evident Global RDP Signature
##
## PROVIDED AS IS WITH NO WARRANTY OR GUARANTEES
## Copyright (c) 2016 Evident.io, Inc., All Rights Reserved
##
from __future__ import print_function

import json
import re
import boto3

print('Loading function')

def lambda_handler(event, context):
    message = event['Records'][0]['Sns']['Message']

    bad_port = 3389
    
    alert = json.loads(message)
    data = alert['data']
    included = alert['included']
    
    for i in included:
        type = i['type']
        if type == "regions":
            regions = i
        if type == "metadata":
            metadata = i
    
    region = re.sub('_','-',regions['attributes']['code'])
    security_group = metadata['attributes']['data']['details']['securityGroup']
    sg_id = security_group['groupId']
    sg_name = security_group['groupName']
    sg_description = security_group['description']
    
    print ("Autoremediating security group " + sg_id, "in region " + region)
    remediation_out = auto_remediate(region, sg_id, bad_port)

    return remediation_out


def auto_remediate(region, sg_id, bad_port):
    ec2 = boto3.client('ec2',region_name=region)
    sg_in = ec2.describe_security_groups(GroupIds=[ sg_id, ])
    for security_group in sg_in['SecurityGroups']:
        if (len(security_group['IpPermissions']) > 0):
            for ip_permission in security_group['IpPermissions']:
                from_port = ip_permission['FromPort']
                to_port = ip_permission['ToPort']
                ip_protocol = ip_permission['IpProtocol']
                for ip_range in ip_permission['IpRanges']:
                    cidr_ip = ip_range['CidrIp']
                    if  cidr_ip == "0.0.0.0/0" and to_port == bad_port:
                        print("Revoking offending rule allowing port %s/%d-%d from IP %s" % (ip_protocol, from_port, to_port, cidr_ip))
                        revoke = ec2.revoke_security_group_ingress(GroupId=sg_id, IpProtocol=ip_protocol, FromPort=from_port, ToPort=to_port,CidrIp=cidr_ip)
        else:
            print("Nothing to revoke")
                    
    sg_out = ec2.describe_security_groups(GroupIds=[ sg_id, ])
    return sg_out['SecurityGroups']
    
