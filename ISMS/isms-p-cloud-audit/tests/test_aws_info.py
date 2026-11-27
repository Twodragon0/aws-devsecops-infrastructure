"""
aws_info.AWSAssetCollector 회귀 테스트 (들여쓰기 복구 후 동작 확인, botocore Stubber)
"""

from datetime import datetime, timezone

import boto3
import pytest
from botocore.stub import Stubber

import aws_info
from utils.config import Config


class FakeManager:
    """AWSClientManager 대체: 서비스별 스텁 클라이언트 반환"""

    def __init__(self, clients):
        self.clients = clients

    def get_client(self, service, region=None):
        return self.clients[service]


@pytest.fixture
def collector():
    session = boto3.Session(aws_access_key_id='testing', aws_secret_access_key='testing',
                            region_name='ap-northeast-2')
    clients = {name: session.client(name) for name in ('ec2', 's3', 'ecr', 'route53')}
    stubbers = {name: Stubber(client) for name, client in clients.items()}
    for stubber in stubbers.values():
        stubber.activate()
    instance = aws_info.AWSAssetCollector.__new__(aws_info.AWSAssetCollector)
    instance.config = Config()
    instance.clients = FakeManager(clients)
    yield instance, stubbers
    for stubber in stubbers.values():
        stubber.assert_no_pending_responses()


def test_ec2_rows_include_all_columns(collector):
    instance, stubs = collector
    stubs['ec2'].add_response('describe_instances', {'Reservations': [{'Instances': [{
        'InstanceId': 'i-0abc', 'InstanceType': 't3.micro', 'ImageId': 'ami-1',
        'Placement': {'AvailabilityZone': 'ap-northeast-2a'}, 'PrivateIpAddress': '10.0.0.5',
        'State': {'Name': 'running'}, 'Tags': [{'Key': 'Name', 'Value': 'web'}]}]}]})
    assert instance.collect_ec2_instances() == [[
        'web', 'i-0abc', 't3.micro', 'Linux/UNIX', 'ami-1', 'ap-northeast-2a', 'N/A', '10.0.0.5', 'N/A', 'running']]


def test_ecr_rows_collected_per_repository(collector):
    instance, stubs = collector
    created = datetime(2026, 11, 1, tzinfo=timezone.utc)
    stubs['ecr'].add_response('describe_repositories', {'repositories': [
        {'repositoryName': 'app-a', 'repositoryUri': 'u/app-a', 'createdAt': created},
        {'repositoryName': 'app-b', 'repositoryUri': 'u/app-b', 'createdAt': created}]})
    assert [row[0] for row in instance.collect_ecr_repositories()] == ['app-a', 'app-b']


def test_bucket_logging_not_enabled(collector):
    instance, stubs = collector
    stubs['s3'].add_response('get_bucket_logging', {}, {'Bucket': 'b'})
    assert instance._get_bucket_logging(instance.clients.get_client('s3'), 'b') == 'Not enabled'


def test_route53_alias_record(collector):
    instance, stubs = collector
    stubs['route53'].add_response('list_hosted_zones', {'HostedZones': [
        {'Id': '/hostedzone/Z1', 'Name': 'example.com.', 'CallerReference': 'r'}], 'Marker': '',
        'IsTruncated': False, 'MaxItems': '100'})
    stubs['route53'].add_response('list_resource_record_sets', {'ResourceRecordSets': [{
        'Name': 'www.example.com.', 'Type': 'A',
        'AliasTarget': {'HostedZoneId': 'Z2', 'DNSName': 'd.cloudfront.net.', 'EvaluateTargetHealth': False}}],
        'IsTruncated': False, 'MaxItems': '100'})
    record = instance.collect_route53_records()[0]
    assert (record['AliasDNSName'], record['Values'], record['TTL']) == ('d.cloudfront.net.', 'N/A', 'N/A')
