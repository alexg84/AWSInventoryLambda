import boto3
import collections
from datetime import datetime
from datetime import timedelta
import csv
from time import gmtime, strftime
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
import os

#Find current owner ID
sts = boto3.client('sts')
identity = sts.get_caller_identity()
ownerId = identity['Account']

#Environment Variables
LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS=os.environ["LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS"]
SES_SMTP_USER=os.environ["SES_SMTP_USER"]
SES_SMTP_PASSWORD=os.environ["EES_SMTP_PASSWORD"]
S3_INVENTORY_BUCKET=os.environ["S3_INVENTORY_BUCKET"]
MAIL_FROM=os.environ["MAIL_FROM"]
MAIL_TO=os.environ["MAIL_TO"]

#Constants
MAIL_SUBJECT="AWS Inventory for " + ownerId
MAIL_BODY=MAIL_SUBJECT + '\n'

#EC2 connection beginning
ec = boto3.client('ec2')
#S3 connection beginning
s3 = boto3.resource('s3')

#lambda function beginning
def lambda_handler(event, context):
    #get to the curren date
    date_fmt = strftime("%Y_%m_%d", gmtime())
    #Give your file path
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    #Give your filename
    filename ='AWS_Resources_' + date_fmt + '.csv'
    csv_file = open(filepath,'w+')

    #boto3 library ec2 API describe region page
    #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_regions
    regions = ec.describe_regions().get('Regions',[] )
    for region in regions:
        reg=region['RegionName']
        regname='REGION :' + reg
        #EC2 connection beginning
        ec2con = boto3.client('ec2',region_name=reg)
        #boto3 library ec2 API describe instance page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_instances
        reservations = ec2con.describe_instances().get(
        'Reservations',[]
        )
        instances = sum(
            [
                [i for i in r['Instances']]
                for r in reservations
            ], [])
        instanceslist = len(instances)
        if instanceslist > 0:
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('','','','','',''))
            csv_file.write("%s,%s\n"%('EC2 INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%('InstanceID','Instance_State','InstanceName','Instance_Type','LaunchTime','Instance_Placement','PublicDnsName','PublicIpAddress','PrivateIpAddress','VpcId','ImageId','VolumeId','PrivateDnsName','KeyName','SubnetId','NetworkInterfaceId','SecurityGroups','Tags'))
            csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            Instancename = 'N/A'
            if 'Tags' in instance:
                    for tags in instance['Tags']:
                        key = tags['Key']
                        if key == 'Name' :
                            Instancename=tags['Value']
            if state =='running':
                instanceid=instance['InstanceId']
                instancetype=instance['InstanceType']
                launchtime =instance['LaunchTime']
                Placement=instance['Placement']['AvailabilityZone']
                PublicDnsName= instance['PublicDnsName'] 
                PublicIpAddress= instance['PublicIpAddress'] if 'PublicIpAddress' in instance else ''
                PrivateIpAddress= instance['PrivateIpAddress']
                VpcId= instance['VpcId']
                ImageId= instance['ImageId']
                
                VolumeId =''
                for BlockDeviceMappings in instance['BlockDeviceMappings']:
                    VolumeId += BlockDeviceMappings['Ebs']['VolumeId']
                
                PrivateDnsName= instance['PrivateDnsName']
                KeyName= instance['KeyName'] if 'KeyName' in instance else ''
                SubnetId= instance['SubnetId']
                
                NetworkInterfaceId =''
                for NetworkInterface in instance['NetworkInterfaces']:
                    NetworkInterfaceId += NetworkInterface['NetworkInterfaceId']
                
                securityGroups = []
                
                for securityGroup in instance['SecurityGroups']:
                    securityGroups.append(securityGroup['GroupName'])
                    
                tags = []
                for tag in instance['Tags']:
                    tags.append('%s: %s' % (tag['Key'], tag['Value']))
                    
                csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"% (instanceid,state,Instancename,instancetype,launchtime,Placement,PublicDnsName,PublicIpAddress,PrivateIpAddress,VpcId,ImageId,VolumeId,PrivateDnsName,KeyName,SubnetId,NetworkInterfaceId,', '.join(securityGroups),', '.join(tags)))
                csv_file.flush()

        for instance in instances:
            state=instance['State']['Name']
            Instancename = 'N/A'
            if 'Tags' in instance:
                    for tags in instance['Tags']:
                        key = tags['Key']
                        if key == 'Name' :
                            Instancename=tags['Value']
            if state =='stopped':
                instanceid=instance['InstanceId']
                instancetype=instance['InstanceType']
                launchtime =instance['LaunchTime']
                Placement=instance['Placement']['AvailabilityZone']
                securityGroups = instance['SecurityGroups']
                PublicDnsName= instance['PublicDnsName'] 
                PrivateIpAddress= instance['PrivateIpAddress']
                VpcId= instance['VpcId']
                ImageId= instance['ImageId']
                PrivateDnsName= instance['PrivateDnsName']
                KeyName= instance['KeyName']
                SubnetId= instance['SubnetId']
                securityGroups = []
                
                for securityGroup in instance['SecurityGroups']:
                    securityGroups.append(securityGroup['GroupName'])
                    
                tags = []
                for tag in instance['Tags']:
                    tags.append('%s: %s' % (tag['Key'], tag['Value']))
                    
                csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"% (instanceid,state,Instancename,instancetype,launchtime,Placement,PublicDnsName,"",PrivateIpAddress,VpcId,ImageId,"",PrivateDnsName,KeyName,SubnetId,"",', '.join(securityGroups),', '.join(tags)))
                csv_file.flush()

        #boto3 library ec2 API describe volumes page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_volumes
        ec2volumes = ec2con.describe_volumes().get('Volumes',[])
        volumes = sum(
            [
                [i for i in r]
                for r in ec2volumes
            ], [])
        volumeslist = len(volumes)
        if volumeslist > 0:
            csv_file.write("%s,%s,%s,%s\n"%('','','',''))
            csv_file.write("%s,%s\n"%('EBS Volume',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"% ('VolumeId','InstanceId','AttachTime','State','VolumeType','SnapshotId','Size','AvailabilityZone','Iops','Encrypted','Tags'))
            csv_file.flush()

        for volume in ec2volumes:
            VolumeType=volume['VolumeType']
            SnapshotId=volume['SnapshotId']
            Size=volume['Size']
            AvailabilityZone=volume['AvailabilityZone']
            Iops=volume['Iops']  if 'iops' in volume else ''
            Encrypted=volume['Encrypted']
            VolumeState=volume['State']
            VolumeId=volume['VolumeId']
            tags = []
            if 'tags' in volume:
                for tag in volume['Tags']:
                    tags.append('%s: %s' % (tag['Key'], tag['Value']))
            
            if VolumeState=="in-use":
                for attachment in volume['Attachments']:
                    AttachmentVolumeId=attachment['VolumeId']
                    InstanceId=attachment['InstanceId']
                    State=attachment['State']
                    AttachTime=attachment['AttachTime']
    
                    csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n"% (VolumeId,InstanceId,AttachTime,State,VolumeType,SnapshotId,Size,AvailabilityZone,Iops,Encrypted,', '.join(tags)))
                    csv_file.flush()
            else:
                    csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n"% (VolumeId,"","",VolumeState,VolumeType,SnapshotId,Size,AvailabilityZone,Iops,Encrypted,', '.join(tags)))
                    csv_file.flush()

        #boto3 library ec2 API describe snapshots page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_snapshots
        ec2snapshot = ec2con.describe_snapshots(OwnerIds=[
            ownerId,
        ],).get('Snapshots',[])
        
        snapshots_counter = 0
        for snapshot in ec2snapshot:
            snapshot_id = snapshot['SnapshotId']
            snapshot_state = snapshot['State']
            tz_info = snapshot['StartTime'].tzinfo
            tags = []
            if 'tags' in snapshot:
                for tag in snapshot['Tags']:
                    tags.append('%s: %s' % (tag['Key'], tag['Value']))
                
            # Snapshots that were not taken within the last configured days do not qualify for auditing
            timedelta_days=-int(LIST_SNAPSHOTS_WITHIN_THE_LAST_N_DAYS)
            if snapshot['StartTime'] > datetime.now(tz_info) + timedelta(days=timedelta_days):
                if snapshots_counter == 0:
                    csv_file.write("%s,%s,%s,%s,%s\n" % ('','','','',''))
                    csv_file.write("%s,%s\n"%('EC2 SNAPSHOT',regname))
                    csv_file.write("%s,%s,%s,%s,%s,%s\n" % ('SnapshotId','VolumeId','StartTime','VolumeSize','Description','Tags'))
                    csv_file.flush()
                snapshots_counter += 1
                SnapshotId=snapshot['SnapshotId']
                VolumeId=snapshot['VolumeId']
                StartTime=snapshot['StartTime']
                VolumeSize=snapshot['VolumeSize']
                Description=snapshot['Description']
                csv_file.write("%s,%s,%s,%s,%s,\"%s\"\n"% (SnapshotId,VolumeId,StartTime,VolumeSize,Description,', '.join(tags)))
                csv_file.flush()

        #boto3 library ec2 API describe addresses page
        #http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.Client.describe_addresses
        addresses = ec2con.describe_addresses().get('Addresses',[] )
        addresseslist = len(addresses)
        if addresseslist > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('EIPS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s\n"%('PublicIp','AllocationId','Domain','InstanceId'))
            csv_file.flush()
            for address in addresses:
                PublicIp=address['PublicIp']
                try:
                    AllocationId=address['AllocationId']
                except:
                    AllocationId="empty"
                Domain=address['Domain']
                if 'InstanceId' in address:
                    instanceId=address['InstanceId']
                else:
                    instanceId='empty'
                csv_file.write("%s,%s,%s,%s\n"%(PublicIp,AllocationId,Domain,instanceId))
                csv_file.flush()

        def printSecGroup(groupType, permission):
            ipProtocol = permission['IpProtocol']
            try:
                fromPort = permission['FromPort']
            except KeyError:
                fromPort = None
            try:
                toPort = permission['ToPort']
            except KeyError:
                toPort = None
            try:
                ipRanges = permission['IpRanges']
            except KeyError:
                ipRanges = []
            ipRangesStr = ''
            for idx, ipRange in enumerate(ipRanges):
                if idx > 0:
                    ipRangesStr += '; '
                ipRangesStr += ipRange['CidrIp']
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%(groupName,groupType,ipProtocol,fromPort,toPort,ipRangesStr))
            csv_file.flush()

        #boto3 library ec2 API describe security groups page
        #http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_security_groups
        securityGroups = ec2con.describe_security_groups(
            Filters = [
                {
                    'Name': 'owner-id',
                    'Values': [
                        ownerId,
                    ]
                }
            ]
        ).get('SecurityGroups')
        if len(securityGroups) > 0:
            csv_file.write("%s,%s,%s,%s,%s\n"%('','','','',''))
            csv_file.write("%s,%s\n"%('SEC GROUPS',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s\n"%('GroupName','GroupType','IpProtocol','FromPort','ToPort','IpRangesStr'))
            csv_file.flush()
            for securityGroup in securityGroups:
                groupName = securityGroup['GroupName']
                ipPermissions = securityGroup['IpPermissions']
                for ipPermission in ipPermissions:
                    groupType = 'ingress'
                    printSecGroup (groupType, ipPermission)
                ipPermissionsEgress = securityGroup['IpPermissionsEgress']
                for ipPermissionEgress in ipPermissionsEgress:
                    groupType = 'egress'
                    printSecGroup (groupType, ipPermissionEgress)

        #RDS Connection beginning
        rdscon = boto3.client('rds',region_name=reg)

        #boto3 library RDS API describe db instances page
        #http://boto3.readthedocs.org/en/latest/reference/services/rds.html#RDS.Client.describe_db_instances
        rdb = rdscon.describe_db_instances().get(
        'DBInstances',[]
        )
        
        rdblist = len(rdb)
        if rdblist > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s,%s\n"%('RDS INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n"%('DBInstanceIdentifier','DBInstanceStatus','DBName','DBInstanceClass','AllocatedStorage','Engine','EngineVersion','DbiResourceId','DBSubnetGroupName','VpcId','DBSubnetGroupDescription','SubnetGroupStatus','AvailabilityZone','MultiAZ','Address','DBInstanceArn','Tags','securityGroups'))
            csv_file.flush()

        for dbinstance in rdb:
            DBInstanceIdentifier = dbinstance['DBInstanceIdentifier']
            DBInstanceClass = dbinstance['DBInstanceClass']
            DBInstanceStatus = dbinstance['DBInstanceStatus']
            AllocatedStorage = dbinstance['AllocatedStorage']
            Engine = dbinstance['Engine']
            EngineVersion = dbinstance['EngineVersion']
            DbiResourceId = dbinstance['DbiResourceId']
            DBSubnetGroupName = dbinstance['DBSubnetGroup']['DBSubnetGroupName']
            VpcId = dbinstance['DBSubnetGroup']['VpcId']
            DBSubnetGroupDescription = dbinstance['DBSubnetGroup']['DBSubnetGroupDescription']
            SubnetGroupStatus = dbinstance['DBSubnetGroup']['SubnetGroupStatus']
            AvailabilityZone = dbinstance['AvailabilityZone']
            MultiAZ = dbinstance['MultiAZ']
            Address = dbinstance['Endpoint']['Address']
            DBInstanceArn= dbinstance['DBInstanceArn']

            Tagsresponse = rdscon.list_tags_for_resource(
                ResourceName=DBInstanceArn
            )
   
            Tags = []
            for tag in Tagsresponse['TagList']:
                Tags.append('%s: %s' % (tag['Key'], tag['Value']))
                    
            securityGroups = []
            if 'VpcSecurityGroups' in dbinstance:
                for securitygroup in dbinstance['VpcSecurityGroups']:
                    securityGroups.append(securitygroup['VpcSecurityGroupId'])
            try:
                DBName = dbinstance['DBName']
            except:
                DBName = "empty"
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"%(DBInstanceIdentifier,DBInstanceStatus,DBName,DBInstanceClass,AllocatedStorage,Engine,EngineVersion,DbiResourceId,DBSubnetGroupName,VpcId,DBSubnetGroupDescription,SubnetGroupStatus,AvailabilityZone,MultiAZ,Address,DBInstanceArn,', '.join(Tags),', '.join(securityGroups)))
            csv_file.flush()
            
        #boto3 library RDS API describe db snapshots page
        #http://boto3.readthedocs.io/en/latest/reference/services/rds.html#RDS.Client.describe_db_snapshots
        rdbsnap = rdscon.describe_db_snapshots().get(
        'DBSnapshots',[]
        )
        rdbsnaplist = len(rdbsnap)
        if rdbsnaplist > 0:
            csv_file.write("%s,%s,%s,%s\n" %('','','',''))
            csv_file.write("%s,%s\n"%('RDS SNAPSHOT',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n"%('Engine','SnapshotCreateTime','AvailabilityZone','DBSnapshotArn','MasterUsername','EngineVersion','Encrypted','VpcId','StorageType','AllocatedStorage','Status','AvailabilityZone','DBSnapshotIdentifier','Tags'))
            csv_file.flush()

        for dbsnapshot in rdbsnap:
            Engine = dbsnapshot['Engine']
            SnapshotCreateTime = dbsnapshot['SnapshotCreateTime']
            AvailabilityZone = dbsnapshot['AvailabilityZone']
            DBSnapshotArn = dbsnapshot['DBSnapshotArn']
            MasterUsername = dbsnapshot['MasterUsername']
            EngineVersion = dbsnapshot['EngineVersion']
            Encrypted = dbsnapshot['Encrypted']
            VpcId = dbsnapshot['VpcId']
            StorageType = dbsnapshot['StorageType']
            AllocatedStorage = dbsnapshot['AllocatedStorage']
            Status = dbsnapshot['Status']
            AvailabilityZone = dbsnapshot['AvailabilityZone']
            DBSnapshotIdentifier = dbsnapshot['DBSnapshotIdentifier']
            
            Tagsresponse = rdscon.list_tags_for_resource(
                ResourceName=DBSnapshotArn
            )
   
            Tags = []
            for tag in Tagsresponse['TagList']:
                Tags.append('%s: %s' % (tag['Key'], tag['Value']))
            
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n"%(Engine,SnapshotCreateTime,AvailabilityZone,DBSnapshotArn,MasterUsername,EngineVersion,Encrypted,VpcId,StorageType,AllocatedStorage,Status,AvailabilityZone,DBSnapshotIdentifier,', '.join(Tags)))
            csv_file.flush()

        #ELB connection beginning
        elbcon = boto3.client('elbv2',region_name=reg)

        #boto3 library ELB API describe db instances page
        #http://boto3.readthedocs.org/en/latest/reference/services/elb.html#ElasticLoadBalancing.Client.describe_load_balancers
        loadbalancer = elbcon.describe_load_balancers().get('LoadBalancers',[])
        loadbalancerlist = len(loadbalancer)
        if loadbalancerlist > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('ELB INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"% ('LoadBalancerName','DNSName','CanonicalHostedZoneNameID','CreatedTime','Scheme','VpcId','LoadBalancerArn','Targetrule','Tags','SecurityGroups'))
            csv_file.flush()

        for load in loadbalancer:
            LoadBalancerName=load['LoadBalancerName']
            DNSName=load['DNSName']
            CanonicalHostedZoneId=load['CanonicalHostedZoneId']
            CreatedTime=load['CreatedTime']
            Scheme=load['Scheme']
            VpcId=load['VpcId']
            LoadBalancerArn= load['LoadBalancerArn']

            Tagslbresponse = elbcon.describe_tags(
            ResourceArns=[LoadBalancerArn]
            )

            Tags = []
            for tagdescriptions in Tagslbresponse['TagDescriptions']:
                for tag in tagdescriptions['Tags']:
                    Tags.append('%s: %s' % (tag['Key'], tag['Value']))
                    
            securityGroups = []
            if 'SecurityGroups' in load:
                for securitygroup in load['SecurityGroups']:
                    securityGroups.append(securityGroup['GroupName'])
                       
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n"% (LoadBalancerName,DNSName,CanonicalHostedZoneId,CreatedTime,Scheme,VpcId,LoadBalancerArn,', '.join(Tags),', '.join(securityGroups)))
            csv_file.flush()
            
        #ELB TATRGET GROUP connection beginning    
        targetcon = boto3.client('elbv2',region_name=reg)   
        
        targetgroup = targetcon.describe_target_groups().get('TargetGroups',[]) 
        targetgrouplist = len(targetgroup)
        if targetgrouplist > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
            csv_file.write("%s,%s\n"%('TATRGET GROUP INSTANCE',regname))
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,\"%s,\",\"%s\"\n"% ('TargetGroupName','Port','VpcId','TargetType','Protocol','HealthCheckProtocol','TargetGroupArn','Tags','TargetsID'))
            csv_file.flush()
            
        for target in targetgroup:
            TargetGroupName=target['TargetGroupName']
            Port=target['Port']
            VpcId=target['VpcId']
            TargetType=target['TargetType']
            Protocol=target['Protocol']
            HealthCheckProtocol=target['HealthCheckProtocol']
            TargetGroupArn=target['TargetGroupArn']
            
            Tagstargetresponse = elbcon.describe_tags(
            ResourceArns=[TargetGroupArn]
            )

            Tags = []
            for tagdescriptions in Tagstargetresponse['TagDescriptions']:
                for tag in tagdescriptions['Tags']:
                    Tags.append('%s: %s' % (tag['Key'], tag['Value']))
                    
            TargetsID = []        
            targetid = elbcon.describe_target_health(
            TargetGroupArn=TargetGroupArn
            )
            
            for targethealthdescriptions in targetid['TargetHealthDescriptions']:
                TargetsID.append('%s' % (targethealthdescriptions['Target']['Id']))
            
            csv_file.write("%s,%s,%s,%s,%s,%s,%s,\"%s\",\"%s\"\n" % (TargetGroupName,Port,VpcId,TargetType,Protocol,HealthCheckProtocol,TargetGroupArn,', '.join(Tags),', '.join(TargetsID)))
            csv_file.flush()
                 
        # CLOUDFRONT connection beginning
        frontcon = boto3.client('cloudfront')

        # boto3 library CLOUDFRONT API cloudfront page
        # https://boto3.readthedocs.io/en/latest/reference/services/cloudfront.html
        cloudfront = frontcon.list_distributions().get('Items', [])
        cloudfrontlist = len(cloudfront)
        if cloudfrontlist > 0:
            csv_file.write("%s,%s,%s,%s\n" % ('', '', '', ''))
            csv_file.write("%s,%s\n" % ('CLOUDFRONT'))
            csv_file.write("%s,%s\n" % ('DomainName','Id'))
            csv_file.flush()

        for front in cloudfront:
            DomainName = cloudfront['DomainName']
            Id = cloudfront['Id']
    
            csv_file.write("%s,%s\n" % (DomainName, Id))
            csv_file.flush()    
            
        #IAM connection beginning
        iam = boto3.client('iam', region_name=reg)

        #boto3 library IAM API
        #http://boto3.readthedocs.io/en/latest/reference/services/iam.html
        csv_file.write("%s,%s,%s,%s\n" % ('','','',''))
        csv_file.write("%s,%s\n"%('IAM',regname))
        csv_file.write("%s,%s\n" % ('User','Policies'))
        csv_file.flush()
        users = iam.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            policies = ''
            user_policies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
            for user_policy in user_policies:
                if(len(policies) > 0):
                    policies += ";"
                policies += user_policy
            attached_user_policies = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
            for attached_user_policy in attached_user_policies:
                if(len(policies) > 0):
                    policies += ";"
                policies += attached_user_policy['PolicyName']
            csv_file.write("%s,%s\n" % (user_name, policies))
            csv_file.flush()

    def mail(fromadd,to, subject, text, attach):
        msg = MIMEMultipart()
        msg['From'] = fromadd
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(text))
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(open(attach, 'rb').read())
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition','attachment; filename="%s"' % os.path.basename(attach))
        msg.attach(part)
        mailServer = smtplib.SMTP("email-smtp.us-east-1.amazonaws.com", 587)
        mailServer.ehlo()
        mailServer.starttls()
        mailServer.ehlo()
        mailServer.login(SES_SMTP_USER, SES_SMTP_PASSWORD)
        mailServer.sendmail(fromadd, to, msg.as_string())
        # Should be mailServer.quit(), but that crashes...
        mailServer.close()

    date_fmt = strftime("%Y_%m_%d", gmtime())
    #Give your file path
    filepath ='/tmp/AWS_Resources_' + date_fmt + '.csv'
    #Save Inventory
    s3.Object(S3_INVENTORY_BUCKET, filename).put(Body=open(filepath, 'rb'))
    #Send Inventory
    mail(MAIL_FROM, MAIL_TO, MAIL_SUBJECT, MAIL_BODY, filepath)
