import base64
import os
import struct
from copy import deepcopy

import boto3
import paramiko
from botocore.exceptions import ClientError
from collections import defaultdict, OrderedDict
from time import sleep

from paramiko.util import deflate_long

from utilities.settings import SettingsError, Settings
from utilities.utils import BenchError, Print, progress_bar


class AWSError(Exception):
    def __init__(self, error):
        assert isinstance(error, ClientError)
        self.message = error.response['Error']['Message']
        self.code = error.response['Error']['Code']
        super().__init__(self.message)


class InstanceManager:
    def __init__(self, settings):
        self.security_group_name = os.environ.get("INSTANCE_SECURITY_GROUP")
        assert isinstance(settings, Settings)
        self.settings = settings
        self.clients = OrderedDict()
        for region in self.settings.aws_regions:
            ec2_client = boto3.client('ec2', region_name=region)
            self.clients[region] = ec2_client

    def delete_keypair(self):
        for region in self.settings.aws_regions:
            ec2_resource = boto3.resource('ec2', region_name=region)
            ec2_client = boto3.client('ec2', region_name=region)
            key_pair = [i.name for i in ec2_resource.key_pairs.all()]
            if "xrbc-coi" in key_pair:
                ec2_client.delete_key_pair(KeyName=self.settings.instance_key_name)
                Print.info(f"{region}: keypair removed from ec2")
        Print.info(f"Finish")

    def create_keypair(self):
        key = paramiko.RSAKey.from_private_key_file(self.settings.instance_key)
        for region in self.settings.aws_regions:
            ec2_resource = boto3.resource('ec2', region_name=region)
            output = b''
            parts = [b'ssh-rsa', deflate_long(key.public_numbers.e), deflate_long(key.public_numbers.n)]
            for part in parts:
                output += struct.pack('>I', len(part)) + part
            public_key = b'ssh-rsa ' + base64.b64encode(output) + b'\n'
            key_name = self.settings.instance_key_name
            ec2_resource.import_key_pair(KeyName=key_name, PublicKeyMaterial=public_key)
            Print.info(f"{region}: keypair imported into ec2")
        Print.info(f"Finish")

    @classmethod
    def make(cls, settings_file='settings.json'):
        try:
            return cls(Settings.load(settings_file))
        except SettingsError as e:
            raise BenchError('Failed to load settings', e)

    def _get(self, state):
        # Possible states are: 'pending', 'running', 'shutting-down',
        # 'terminated', 'stopping', and 'stopped'.
        ids, ips = defaultdict(list), defaultdict(list)
        for region, client in self.clients.items():
            r = client.describe_instances(
                Filters=[
                    {
                        'Name': 'tag:Name',
                        'Values': [self.settings.instance_name]
                    },
                    {
                        'Name': 'instance-state-name',
                        'Values': state
                    }
                ]
            )
            instances = [y for x in r['Reservations'] for y in x['Instances']]
            for x in instances:
                ids[region] += [x['InstanceId']]
                if 'PublicIpAddress' in x:
                    ips[region] += [x['PublicIpAddress']]
        return ids, ips

    def _wait(self, state):
        # Possible states are: 'pending', 'running', 'shutting-down',
        # 'terminated', 'stopping', and 'stopped'.
        while True:
            sleep(1)
            ids, _ = self._get(state)
            if sum(len(x) for x in ids.values()) == 0:
                break

    def _create_security_group(self, client):
        client.create_security_group(
            Description='xrbc-coi-node',
            GroupName=self.security_group_name,
        )

        client.authorize_security_group_ingress(
            GroupName=self.security_group_name,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'Debug SSH access',
                    }],
                    'Ipv6Ranges': [{
                        'CidrIpv6': '::/0',
                        'Description': 'Debug SSH access',
                    }],
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': self.settings.from_port,
                    'ToPort': self.settings.to_port,
                    'IpRanges': [{
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'Dag port',
                    }],
                    'Ipv6Ranges': [{
                        'CidrIpv6': '::/0',
                        'Description': 'Dag port',
                    }],
                }
            ]
        )

    def _get_ami(self, client):
        # The AMI changes with regions.
        response = client.describe_images(
            Filters=[{
                'Name': 'description',
                'Values': ['Canonical, Ubuntu, 20.04 LTS, amd64 focal image build on 2022-09-14']
            }]
        )
        return response['Images'][0]['ImageId']

    def create_single_instance(self, client):
        client.run_instances(
            ImageId=self._get_ami(client),
            InstanceType=self.settings.instance_type,
            KeyName=self.settings.instance_key_name,
            MaxCount=1,
            MinCount=1,
            SecurityGroups=[self.security_group_name],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{
                    'Key': 'Name',
                    'Value': self.settings.instance_name
                }]
            }],
            EbsOptimized=True,
            BlockDeviceMappings=[{
                'DeviceName': '/dev/sda1',
                'Ebs': {
                    'VolumeType': 'gp2',
                    'VolumeSize': 200,
                    'DeleteOnTermination': True
                }
            }],
        )

    def create_instances(self, instances):
        assert isinstance(instances, int) and instances > 0
        instance_left = deepcopy(instances)

        # Create the security group in every region.
        for client in self.clients.values():
            try:
                self._create_security_group(client)
            except ClientError as e:
                error = AWSError(e)
                if error.code != 'InvalidGroup.Duplicate':
                    raise BenchError('Failed to create security group', error)
        try:
            # Create all instances.
            total_ec2_client = len(self.clients.values())
            while instance_left > 0:
                client_region = self.settings.aws_regions[instance_left % total_ec2_client]
                self.create_single_instance(self.clients[client_region])
                Print.info(f"{client_region}: created ec2 instance")
                instance_left -= 1

            # Wait for the instances to boot.
            Print.info('Waiting for all instances to boot...')
            self._wait(['pending'])
            Print.heading(f'Successfully created {instances} new instances')
        except ClientError as e:
            raise BenchError('Failed to create AWS instances', AWSError(e))

    def terminate_instances(self):
        try:
            ids, _ = self._get(['pending', 'running', 'stopping', 'stopped'])
            size = sum(len(x) for x in ids.values())
            if size == 0:
                Print.heading(f'All instances are shut down')
                return

            # Terminate instances.
            for region, client in self.clients.items():
                if ids[region]:
                    client.terminate_instances(InstanceIds=ids[region])

            # Wait for all instances to properly shut down.
            Print.info('Waiting for all instances to shut down...')
            self._wait(['shutting-down'])
            for client in self.clients.values():
                client.delete_security_group(
                    GroupName=self.security_group_name
                )

            Print.heading(f'Testbed of {size} instances destroyed')
        except ClientError as e:
            raise BenchError('Failed to terminate instances', AWSError(e))

    def start_instances(self, max):
        size = 0
        try:
            ids, _ = self._get(['stopping', 'stopped'])
            for region, client in self.clients.items():
                if ids[region]:
                    target = ids[region]
                    target = target if len(target) < max else target[:max]
                    size += len(target)
                    client.start_instances(InstanceIds=target)
            Print.heading(f'Starting {size} instances')
        except ClientError as e:
            raise BenchError('Failed to start instances', AWSError(e))

    def stop_instances(self):
        try:
            ids, _ = self._get(['pending', 'running'])
            for region, client in self.clients.items():
                if ids[region]:
                    client.stop_instances(InstanceIds=ids[region])
            size = sum(len(x) for x in ids.values())
            Print.heading(f'Stopping {size} instances')
        except ClientError as e:
            raise BenchError(AWSError(e))

    def hosts(self, flat=False):
        try:
            _, ips = self._get(['pending', 'running'])
            return [x for y in ips.values() for x in y] if flat else ips
        except ClientError as e:
            raise BenchError('Failed to gather instances IPs', AWSError(e))

    def print_info(self):
        hosts = self.hosts()
        key = self.settings.instance_key
        text = ''
        for region, ips in hosts.items():
            text += f'\n Region: {region.upper()}\n'
            for i, ip in enumerate(ips):
                new_line = '\n' if (i + 1) % 6 == 0 else ''
                text += f'{new_line} {i}\tssh -i {key} ubuntu@{ip}\n'
        print(
            '\n'
            '----------------------------------------------------------------\n'
            ' INFO:\n'
            '----------------------------------------------------------------\n'
            f' Available machines: {sum(len(x) for x in hosts.values())}\n'
            f'{text}'
            '----------------------------------------------------------------\n'
        )
