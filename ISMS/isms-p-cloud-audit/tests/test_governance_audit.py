"""
governance_audit 단위 테스트 (botocore Stubber, 실제 AWS 호출 없음)

시나리오:
- CloudTrail 변조 차단 Deny 탐지/미탐지, ArnNotLike 예외 추출
- 관리 계정(조직) vs 단독 계정(AWSOrganizationsNotInUseException) vs 멤버 계정
- S3 데이터 이벤트(기본/고급 이벤트 선택기) 수집 여부
- AccessDenied 처리 (중단 없이 UNKNOWN)
"""

import csv
import json
from typing import Any, Dict, List

import boto3
import pytest
from botocore.stub import Stubber

import governance_audit as ga
from utils.config import Config

ORG_ID = 'o-exampleorgid'
ROOT_ID = 'r-ab12'
OU_ID = 'ou-ab12-11111111'
MGMT = '111122223333'
LOG_ARCHIVE = '444455556666'
TRAIL_ARN = f'arn:aws:cloudtrail:ap-northeast-2:{MGMT}:trail/org-trail'

TAMPER_SCP = {
    'Version': '2012-10-17',
    'Statement': [{
        'Sid': 'DenyCloudTrailTamper',
        'Effect': 'Deny',
        'Action': [
            'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail',
            'cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors',
        ],
        'Resource': '*',
        'Condition': {'ArnNotLike': {
            'aws:PrincipalArn': 'arn:aws:iam::*:role/AWSControlTowerExecution',
        }},
    }],
}

OTHER_SCP = {
    'Version': '2012-10-17',
    'Statement': [{'Effect': 'Deny', 'Action': 'ec2:RunInstances', 'Resource': '*'}],
}

RCP_S3 = {
    'Version': '2012-10-17',
    'Statement': [{
        'Effect': 'Deny', 'Principal': '*', 'Action': 's3:*', 'Resource': '*',
        'Condition': {'StringNotEqualsIfExists': {'aws:PrincipalOrgID': ORG_ID}},
    }],
}


def make_client(service: str):
    """자격 증명이 고정된 오프라인 클라이언트"""
    session = boto3.Session(
        aws_access_key_id='testing', aws_secret_access_key='testing',
        region_name='ap-northeast-2',
    )
    return session.client(service)


@pytest.fixture
def stubs():
    """서비스별 (client, Stubber) 생성 후 종료 시 검증"""
    created: Dict[str, Any] = {}
    for service in ('sts', 'organizations', 'cloudtrail', 's3', 'controltower'):
        client = make_client(service)
        stubber = Stubber(client)
        created[service] = (client, stubber)
    yield created
    for _, stubber in created.values():
        stubber.assert_no_pending_responses()
        stubber.deactivate()


def build_auditor(stubs, tmp_path) -> ga.GovernanceAuditor:
    config = Config()
    config.output_dir = str(tmp_path)
    for _, stubber in stubs.values():
        stubber.activate()
    return ga.GovernanceAuditor(config, clients={k: v[0] for k, v in stubs.items()})


def stub_identity(stubs, account: str) -> None:
    stubs['sts'][1].add_response('get_caller_identity', {
        'Account': account, 'Arn': f'arn:aws:sts::{account}:assumed-role/Audit/session', 'UserId': 'AID'})


def by_id(report: Dict[str, Any]) -> Dict[str, str]:
    return {f['check_id']: f['status'] for f in report['findings']}


def policy_summary(policy_id: str, name: str, policy_type: str, managed: bool = False):
    return {
        'Id': policy_id, 'Arn': f'arn:aws:organizations::{MGMT}:policy/{ORG_ID}/{policy_id}',
        'Name': name, 'Type': policy_type, 'AwsManaged': managed,
    }


def add_policy(org: Stubber, summary: Dict[str, Any], content: Dict[str, Any],
               targets: List[Dict[str, Any]]) -> None:
    org.add_response('describe_policy', {
        'Policy': {'PolicySummary': summary, 'Content': json.dumps(content)}},
        {'PolicyId': summary['Id']})
    org.add_response('list_targets_for_policy', {'Targets': targets}, {'PolicyId': summary['Id']})


ROOT_TARGET = {'TargetId': ROOT_ID, 'Arn': f'arn:aws:organizations::{MGMT}:root/{ORG_ID}/{ROOT_ID}',
               'Name': 'Root', 'Type': 'ROOT'}


def stub_org_management(org: Stubber, scp_content: Dict[str, Any], scp_attached: bool = True) -> None:
    """관리 계정: 조직/루트/OU 트리/SCP/RCP 응답"""
    org.add_response('describe_organization', {'Organization': {
        'Id': ORG_ID, 'FeatureSet': 'ALL', 'MasterAccountId': MGMT}})
    org.add_response('list_roots', {'Roots': [{
        'Id': ROOT_ID, 'Name': 'Root', 'PolicyTypes': [
            {'Type': 'SERVICE_CONTROL_POLICY', 'Status': 'ENABLED'},
            {'Type': 'RESOURCE_CONTROL_POLICY', 'Status': 'ENABLED'},
        ]}]})
    org.add_response('list_accounts_for_parent', {'Accounts': [
        {'Id': MGMT, 'Name': 'management', 'Status': 'ACTIVE'}]}, {'ParentId': ROOT_ID})
    org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': [
        {'Id': OU_ID, 'Name': 'Security', 'Arn': f'arn:aws:organizations::{MGMT}:ou/{ORG_ID}/{OU_ID}'}]},
        {'ParentId': ROOT_ID})
    org.add_response('list_accounts_for_parent', {'Accounts': [
        {'Id': LOG_ARCHIVE, 'Name': 'log-archive', 'Status': 'ACTIVE'}]}, {'ParentId': OU_ID})
    org.add_response('list_organizational_units_for_parent', {'OrganizationalUnits': []},
                     {'ParentId': OU_ID})

    full = policy_summary('p-FullAWSAccess', 'FullAWSAccess', 'SERVICE_CONTROL_POLICY', True)
    custom = policy_summary('p-tamper1234', 'deny-cloudtrail-tamper', 'SERVICE_CONTROL_POLICY')
    org.add_response('list_policies', {'Policies': [full, custom]}, {'Filter': 'SERVICE_CONTROL_POLICY'})
    add_policy(org, full, {'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}, [ROOT_TARGET])
    add_policy(org, custom, scp_content, [ROOT_TARGET] if scp_attached else [])

    rcp = policy_summary('p-rcp12345', 'rcp-s3-org-only', 'RESOURCE_CONTROL_POLICY')
    org.add_response('list_policies', {'Policies': [rcp]}, {'Filter': 'RESOURCE_CONTROL_POLICY'})
    add_policy(org, rcp, RCP_S3, [ROOT_TARGET])


def stub_trail(ct: Stubber, selectors: Dict[str, Any], org_trail: bool = True,
               bucket: str = 'aws-controltower-logs-example') -> None:
    ct.add_response('describe_trails', {'trailList': [{
        'Name': 'org-trail', 'TrailARN': TRAIL_ARN, 'HomeRegion': 'ap-northeast-2',
        'S3BucketName': bucket, 'IsMultiRegionTrail': True,
        'IsOrganizationTrail': org_trail, 'LogFileValidationEnabled': True,
        'KmsKeyId': f'arn:aws:kms:ap-northeast-2:{LOG_ARCHIVE}:key/example',
    }]}, {'includeShadowTrails': True})
    ct.add_response('get_trail_status', {'IsLogging': True}, {'Name': TRAIL_ARN})
    ct.add_response('get_event_selectors', dict({'TrailARN': TRAIL_ARN}, **selectors),
                    {'TrailName': TRAIL_ARN})


ADVANCED_S3_READ = {'AdvancedEventSelectors': [{
    'Name': 'S3 GetObject on sensitive bucket',
    'FieldSelectors': [
        {'Field': 'eventCategory', 'Equals': ['Data']},
        {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']},
        {'Field': 'eventName', 'Equals': ['GetObject']},
        {'Field': 'resources.ARN', 'StartsWith': ['arn:aws:s3:::pii-bucket/']},
    ],
}]}

MANAGEMENT_ONLY = {'EventSelectors': [{
    'ReadWriteType': 'All', 'IncludeManagementEvents': True, 'DataResources': []}]}


# ----------------------------------------------------------------------
# 순수 분석 함수
# ----------------------------------------------------------------------
class TestAnalyzeTamperDeny:
    def test_detects_full_deny_and_arn_not_like_exception(self):
        result = ga.analyze_tamper_deny(TAMPER_SCP)
        assert result['missing_actions'] == []
        assert result['statements'] == ['DenyCloudTrailTamper']
        assert result['exceptions'] == [{
            'sid': 'DenyCloudTrailTamper', 'operator': 'ArnNotLike', 'key': 'aws:PrincipalArn',
            'values': ['arn:aws:iam::*:role/AWSControlTowerExecution'],
        }]

    def test_not_detected_for_unrelated_deny(self):
        result = ga.analyze_tamper_deny(OTHER_SCP)
        assert result['covered_actions'] == []
        assert sorted(result['missing_actions']) == sorted(ga.TAMPER_ACTIONS)

    def test_allow_statement_is_ignored(self):
        doc = {'Statement': [{'Effect': 'Allow', 'Action': 'cloudtrail:*', 'Resource': '*'}]}
        assert ga.analyze_tamper_deny(doc)['covered_actions'] == []

    def test_wildcard_and_partial_coverage(self):
        assert ga.analyze_tamper_deny(
            {'Statement': {'Effect': 'Deny', 'Action': 'CloudTrail:*', 'Resource': '*'}}
        )['missing_actions'] == []
        partial = ga.analyze_tamper_deny(
            {'Statement': [{'Effect': 'Deny', 'Action': 'cloudtrail:StopLogging', 'Resource': '*'}]})
        assert partial['covered_actions'] == ['cloudtrail:StopLogging']
        assert 'cloudtrail:DeleteTrail' in partial['missing_actions']

    def test_not_action_deny(self):
        doc = {'Statement': [{'Effect': 'Deny', 'NotAction': ['cloudtrail:UpdateTrail'],
                              'Resource': '*'}]}
        result = ga.analyze_tamper_deny(doc)
        assert result['missing_actions'] == ['cloudtrail:UpdateTrail']


class TestAnalyzeEventSelectors:
    def test_advanced_get_object_on_bucket(self):
        result = ga.analyze_event_selectors(ADVANCED_S3_READ)
        assert result['selector_type'] == 'advanced'
        assert result['s3_read'] is True
        assert result['read_buckets'] == ['pii-bucket']
        assert result['s3_write'] is False  # eventName=GetObject 만 수집

    def test_advanced_write_only_has_no_read(self):
        result = ga.analyze_event_selectors({'AdvancedEventSelectors': [{'FieldSelectors': [
            {'Field': 'eventCategory', 'Equals': ['Data']},
            {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']},
            {'Field': 'readOnly', 'Equals': ['false']},
        ]}]})
        assert result['s3_read'] is False
        assert result['write_buckets'] == ['*']

    def test_basic_all_buckets(self):
        result = ga.analyze_event_selectors({'EventSelectors': [{
            'ReadWriteType': 'ReadOnly',
            'DataResources': [{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}]}]})
        assert result == {'selector_type': 'basic', 's3_read': True, 's3_write': False,
                          'read_buckets': ['*'], 'write_buckets': [], 'excluded': []}

    def test_management_events_only(self):
        result = ga.analyze_event_selectors(MANAGEMENT_ONLY)
        assert result['s3_read'] is False and result['s3_write'] is False

    def test_mask_account_ids(self):
        assert ga.mask_account_ids(f'arn:aws:iam::{MGMT}:root') == 'arn:aws:iam::********3333:root'


# ----------------------------------------------------------------------
# 수집 + 평가 (Stubber)
# ----------------------------------------------------------------------
def test_management_account_all_pass_except_access_denied_control_tower(stubs, tmp_path):
    stubs['sts'][1].add_response('get_caller_identity', {
        'Account': MGMT, 'Arn': f'arn:aws:sts::{MGMT}:assumed-role/Audit/session', 'UserId': 'AID'})
    stub_org_management(stubs['organizations'][1], TAMPER_SCP)
    stub_trail(stubs['cloudtrail'][1], ADVANCED_S3_READ)
    stubs['s3'][1].add_response('list_buckets', {'Buckets': [{'Name': 'my-app-bucket'}]})
    stubs['controltower'][1].add_client_error(
        'list_landing_zones', 'AccessDeniedException', 'denied', 403)

    report = build_auditor(stubs, tmp_path).run()
    status = by_id(report)

    assert status['GOV-ORG-01'] == 'PASS'
    assert status['GOV-ORG-02'] == 'PASS'
    assert status['GOV-ORG-03'] == 'PASS'
    assert status['GOV-ORG-04'] == 'PASS'
    for check in ('GOV-CT-01', 'GOV-CT-02', 'GOV-CT-03', 'GOV-CT-04', 'GOV-CT-05', 'GOV-LOG-01'):
        assert status[check] == 'PASS', check
    assert status['GOV-CT-06'] == 'UNKNOWN'  # CloudWatch Logs 미연동 → 수동 확인
    assert status['GOV-CTW-01'] == 'UNKNOWN'  # AccessDenied 는 중단 없이 UNKNOWN

    tamper = next(f for f in report['findings'] if f['check_id'] == 'GOV-ORG-03')
    assert tamper['evidence']['exceptions'][0]['operator'] == 'ArnNotLike'
    assert 'GOV-ORG-03' in [f['check_id'] for f in report['findings'] if '2.9.4' in f['isms_p']]

    tree = report['raw']['organization']['tree']
    assert tree['children'][0]['name'] == 'Security'
    assert tree['children'][0]['accounts'][0]['name'] == 'log-archive'
    assert {'api': 'controltower:ListLandingZones', 'code': 'AccessDeniedException'} in report['errors']


def test_tamper_deny_missing_and_unattached(stubs, tmp_path):
    stub_identity(stubs, MGMT)
    stub_org_management(stubs['organizations'][1], TAMPER_SCP, scp_attached=False)
    stub_trail(stubs['cloudtrail'][1], MANAGEMENT_ONLY)
    stubs['s3'][1].add_response('list_buckets', {'Buckets': []})
    stubs['controltower'][1].add_response('list_landing_zones', {'landingZones': [
        {'arn': f'arn:aws:controltower:ap-northeast-2:{MGMT}:landingzone/EXAMPLE'}]})
    stubs['controltower'][1].add_response('get_landing_zone', {'landingZone': {
        'version': '3.3', 'manifest': {}, 'status': 'ACTIVE',
        'driftStatus': {'status': 'DRIFTED'}}})
    stubs['controltower'][1].add_response('list_enabled_controls', {'enabledControls': []})

    report = build_auditor(stubs, tmp_path).run()
    status = by_id(report)

    assert status['GOV-ORG-02'] == 'FAIL'  # 사용자 정의 SCP 가 연결되지 않음
    assert status['GOV-ORG-03'] == 'FAIL'
    tamper = next(f for f in report['findings'] if f['check_id'] == 'GOV-ORG-03')
    assert tamper['evidence']['unattached_policies'] == ['deny-cloudtrail-tamper']
    assert status['GOV-CT-05'] == 'FAIL'  # 관리 이벤트만 수집
    assert status['GOV-CTW-01'] == 'FAIL'  # 드리프트


def test_standalone_account(stubs, tmp_path):
    stub_identity(stubs, MGMT)
    stubs['organizations'][1].add_client_error(
        'describe_organization', 'AWSOrganizationsNotInUseException', 'not in use', 400)
    stub_trail(stubs['cloudtrail'][1], MANAGEMENT_ONLY, org_trail=False, bucket='local-trail-bucket')
    stubs['s3'][1].add_response('list_buckets', {'Buckets': [{'Name': 'local-trail-bucket'}]})
    stubs['controltower'][1].add_response('list_landing_zones', {'landingZones': []})

    report = build_auditor(stubs, tmp_path).run()
    status = by_id(report)

    assert report['raw']['organization'] == {'status': 'standalone'}
    for check in ('GOV-ORG-01', 'GOV-ORG-02', 'GOV-ORG-03', 'GOV-ORG-04'):
        assert status[check] == 'FAIL', check
    assert status['GOV-CT-01'] == 'FAIL'  # 조직 추적 없음
    assert status['GOV-CT-02'] == 'PASS'  # 계정 추적이라도 다중 리전
    assert status['GOV-LOG-01'] == 'FAIL'  # 같은 계정 버킷
    assert status['GOV-CTW-01'] == 'FAIL'
    assert report['errors'] == []


def test_member_account_access_denied_everywhere(stubs, tmp_path):
    stub_identity(stubs, LOG_ARCHIVE)
    stubs['organizations'][1].add_response('describe_organization', {'Organization': {
        'Id': ORG_ID, 'FeatureSet': 'ALL', 'MasterAccountId': MGMT}})
    stubs['organizations'][1].add_client_error('list_roots', 'AccessDeniedException', 'denied', 400)
    stubs['cloudtrail'][1].add_client_error('describe_trails', 'AccessDeniedException', 'denied', 400)
    stubs['s3'][1].add_client_error('list_buckets', 'AccessDenied', 'denied', 403)
    stubs['controltower'][1].add_client_error('list_landing_zones', 'AccessDeniedException', 'denied', 403)

    report = build_auditor(stubs, tmp_path).run()
    status = by_id(report)

    assert status['GOV-ORG-01'] == 'PASS'  # DescribeOrganization 은 멤버 계정도 가능
    for check in ('GOV-ORG-02', 'GOV-ORG-03', 'GOV-ORG-04', 'GOV-CT-01', 'GOV-CT-05',
                  'GOV-LOG-01', 'GOV-CTW-01'):
        assert status[check] == 'UNKNOWN', check
    assert report['summary'] == {'PASS': 1, 'FAIL': 0, 'UNKNOWN': 11}
    assert {e['api'] for e in report['errors']} == {
        'organizations:ListRoots', 'cloudtrail:DescribeTrails',
        's3:ListAllMyBuckets', 'controltower:ListLandingZones'}


def test_trail_status_access_denied_is_unknown(stubs, tmp_path):
    stubs['sts'][1].add_client_error('get_caller_identity', 'ExpiredToken', 'expired', 400)
    stubs['organizations'][1].add_client_error(
        'describe_organization', 'AccessDeniedException', 'denied', 400)
    ct = stubs['cloudtrail'][1]
    ct.add_response('describe_trails', {'trailList': [{
        'Name': 'org-trail', 'TrailARN': TRAIL_ARN, 'HomeRegion': 'ap-northeast-2',
        'IsOrganizationTrail': True, 'IsMultiRegionTrail': True}]}, {'includeShadowTrails': True})
    ct.add_client_error('get_trail_status', 'AccessDeniedException', 'denied', 400)
    ct.add_client_error('get_event_selectors', 'AccessDeniedException', 'denied', 400)
    stubs['s3'][1].add_response('list_buckets', {'Buckets': []})
    stubs['controltower'][1].add_response('list_landing_zones', {'landingZones': []})

    report = build_auditor(stubs, tmp_path).run()
    status = by_id(report)

    assert report['report_metadata']['caller'] == {'account_id': None, 'arn': None}
    assert status['GOV-ORG-01'] == 'UNKNOWN'
    assert status['GOV-ORG-03'] == 'UNKNOWN'
    assert status['GOV-CT-01'] == 'UNKNOWN'


def test_export_writes_masked_json_and_csv(stubs, tmp_path):
    stub_identity(stubs, MGMT)
    stubs['organizations'][1].add_client_error(
        'describe_organization', 'AWSOrganizationsNotInUseException', 'not in use', 400)
    stub_trail(stubs['cloudtrail'][1], ADVANCED_S3_READ, org_trail=False)
    stubs['s3'][1].add_response('list_buckets', {'Buckets': []})
    stubs['controltower'][1].add_response('list_landing_zones', {'landingZones': []})

    auditor = build_auditor(stubs, tmp_path)
    report = auditor.run()
    json_path, csv_path = auditor.export(report, mask=True)

    text = json_path.read_text(encoding='utf-8')
    assert MGMT not in text and '********3333' in text
    with open(csv_path, encoding='utf-8-sig') as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == len(report['findings']) == 12
    ct05 = next(r for r in rows if r['check_id'] == 'GOV-CT-05')
    assert ct05['status'] == 'PASS'
    assert ct05['isms_p_title'] == '로그 및 접속기록 관리 / 이상행위 분석 및 모니터링'
    assert all(r['collected_at'] for r in rows)
