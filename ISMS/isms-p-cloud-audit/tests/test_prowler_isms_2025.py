"""
prowler_isms_2025 의 Prowler 5.x CLI 호출·OCSF 파싱 테스트 (Prowler 미실행, subprocess 모킹)
"""

import subprocess
from pathlib import Path
from typing import Any, Dict, List

import pytest

import prowler_isms_2025 as pi
from utils.config import Config


@pytest.fixture
def assessor(tmp_path, monkeypatch):
    monkeypatch.setattr(pi.ProwlerISMS2025, 'check_prowler_installed', lambda self: True)
    config = Config()
    config.output_dir = str(tmp_path)
    config.aws_profile = 'twodragon'
    config.aws_region = 'ap-northeast-2'
    return pi.ProwlerISMS2025(config)


def capture_run(monkeypatch) -> List[List[str]]:
    calls: List[List[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

    monkeypatch.setattr(pi.subprocess, 'run', fake_run)
    return calls


def option_values(cmd: List[str], option: str) -> List[str]:
    """옵션 뒤에 오는 값들 (다음 '-' 옵션 전까지)"""
    index = cmd.index(option)
    values = []
    for token in cmd[index + 1:]:
        if token.startswith('-'):
            break
        values.append(token)
    return values


def test_default_scan_uses_prowler5_outputs_and_isms_p_compliance(assessor, monkeypatch, tmp_path):
    calls = capture_run(monkeypatch)
    output = assessor.run_prowler_scan(output_format='json', compliance_framework=pi.ISMS_P_COMPLIANCE)
    cmd = calls[0]

    assert cmd[:2] == ['prowler', 'aws']
    assert option_values(cmd, '-M') == ['csv', 'json-ocsf']
    assert option_values(cmd, '-o') == [str(tmp_path)]
    assert option_values(cmd, '--compliance') == ['kisa_isms_p_2023_korean_aws']
    assert option_values(cmd, '--region') == ['ap-northeast-2']
    assert '-f' not in cmd and '-c' not in cmd  # Prowler 5: -f=리전 필터, -c=체크 지정
    name = option_values(cmd, '-F')[0]
    assert output == Path(tmp_path) / f'{name}.ocsf.json'


def test_services_are_space_separated_and_exclusive_with_compliance(assessor, monkeypatch):
    calls = capture_run(monkeypatch)
    assessor.run_prowler_scan(services=['ec2', 's3'])
    assert option_values(calls[0], '-s') == ['ec2', 's3']

    assessor.run_prowler_scan(compliance_framework='iso27001_2022_aws', services=['ec2'])
    assert '-s' not in calls[1]  # Prowler 5 에서 --compliance 와 -s 는 동시 사용 불가


def test_full_assessment_defaults_to_isms_p(assessor, monkeypatch):
    seen: Dict[str, Any] = {}

    def fake_scan(output_format='json', compliance_framework=None, services=None):
        seen['compliance'] = compliance_framework
        raise pi.AssetCollectionError('stop')

    monkeypatch.setattr(assessor, 'identify_assets', lambda: [])
    monkeypatch.setattr(assessor, 'run_prowler_scan', fake_scan)
    with pytest.raises(pi.AssetCollectionError):
        assessor.run_full_assessment()
    assert seen['compliance'] == 'kisa_isms_p_2023_korean_aws'


def test_parse_ocsf_finding(assessor):
    item = {
        'message': 'Trail is not logging', 'status': 'New', 'status_code': 'FAIL', 'severity': 'High',
        'metadata': {'event_code': 'cloudtrail_multi_region_enabled'},
        'finding_info': {'title': 'Ensure CloudTrail is enabled in all regions'},
        'resources': [{'uid': 'arn:aws:cloudtrail:ap-northeast-2:111122223333:trail/t',
                       'region': 'ap-northeast-2', 'group': {'name': 'cloudtrail'}}],
        'remediation': {'desc': 'Enable multi-region trail', 'references': []},
        'unmapped': {'compliance': {'KISA-ISMS-P-2023-korean': ['2.9.4']}},
    }
    finding = assessor._parse_finding(item)
    assert finding.check_id == 'cloudtrail_multi_region_enabled'
    assert finding.status == 'FAIL'
    assert finding.service == 'cloudtrail'
    assert finding.region == 'ap-northeast-2'
    assert finding.resource_id.endswith(':trail/t')
    assert finding.check_title.startswith('Ensure CloudTrail')
    assert finding.remediation == 'Enable multi-region trail'
    assert finding.description == 'Trail is not logging'
    assert finding.risk_level == pi.RiskLevel.HIGH  # FAIL 은 Prowler 심각도를 그대로 사용


def test_parse_legacy_finding_unchanged(assessor):
    finding = assessor._parse_finding({'CheckID': 'x', 'Status': 'PASS', 'Severity': 'low',
                                       'ServiceName': 's3', 'Region': 'ap-northeast-2',
                                       'ResourceId': 'b', 'Message': 'ok', 'Remediation': 'none'})
    assert (finding.check_id, finding.status, finding.service, finding.remediation) == ('x', 'PASS', 's3', 'none')


# --- 위험 평가: OCSF 발견 사항이 자산·요약에 반영되는지 (합성 데이터, 실제 계정 아님) ---

BUCKET_ARN = 'arn:aws:s3:::example-bucket'
ROLE_ARN = 'arn:aws:iam::123456789012:role/example-role'


def ocsf_item(status: str, severity: str, uid: str, check: str) -> Dict[str, Any]:
    is_bucket = uid == BUCKET_ARN
    return {
        'message': f'{check} {status}', 'status_code': status, 'severity': severity,
        'metadata': {'event_code': check},
        'finding_info': {'title': check},
        'resources': [{
            'uid': uid, 'name': 'example-bucket' if is_bucket else 'example-role',
            'type': 'AwsS3Bucket' if is_bucket else 'AwsIamRole',
            'region': 'ap-northeast-2' if is_bucket else 'global',
            'group': {'name': 's3' if is_bucket else 'iam'},
        }],
        'remediation': {'desc': 'fix it'},
        'unmapped': {'compliance': {}},
    }


SYNTHETIC_OCSF = [
    ocsf_item('FAIL', 'Critical', ROLE_ARN, 'iam_role_admin'),
    ocsf_item('FAIL', 'High', ROLE_ARN, 'iam_role_cross_account'),
    ocsf_item('FAIL', 'Medium', BUCKET_ARN, 's3_bucket_versioning'),
    ocsf_item('FAIL', 'Low', BUCKET_ARN, 's3_bucket_lifecycle'),
    ocsf_item('PASS', 'Critical', BUCKET_ARN, 's3_bucket_public_access'),
    ocsf_item('PASS', 'High', ROLE_ARN, 'iam_role_mfa'),
    ocsf_item('MANUAL', 'Medium', BUCKET_ARN, 's3_bucket_manual_review'),
    ocsf_item('PASS', 'Low', BUCKET_ARN, 's3_bucket_tags'),
]


@pytest.fixture
def synthetic_findings(assessor, tmp_path):
    path = tmp_path / 'synthetic.ocsf.json'
    path.write_text(pi.json.dumps(SYNTHETIC_OCSF), encoding='utf-8')
    return assessor.parse_prowler_results(path)


def test_fail_severity_maps_one_to_one_and_pass_manual_are_info(assessor):
    level = assessor._determine_risk_level
    assert [level('FAIL', s) for s in ('Critical', 'High', 'Medium', 'Low')] == [
        pi.RiskLevel.CRITICAL, pi.RiskLevel.HIGH, pi.RiskLevel.MEDIUM, pi.RiskLevel.LOW]
    assert level('PASS', 'Critical') == pi.RiskLevel.INFO
    assert level('MANUAL', 'High') == pi.RiskLevel.INFO


def test_assets_are_derived_from_ocsf_resources(assessor, synthetic_findings):
    assets = assessor.assets_from_findings(synthetic_findings)
    by_id = {a.asset_id: a for a in assets}
    assert set(by_id) == {BUCKET_ARN, ROLE_ARN}
    assert by_id[BUCKET_ARN].asset_name == 'example-bucket'
    assert by_id[BUCKET_ARN].asset_type == 'AwsS3Bucket'
    assert by_id[ROLE_ARN].service == 'iam'


def test_inventory_asset_matches_ocsf_resource_by_name(assessor, synthetic_findings):
    bucket = pi.Asset(asset_id='example-bucket', asset_type='S3', asset_name='example-bucket', service='s3',
                      region='ap-northeast-2', importance=pi.AssetImportance.HIGH,
                      confidentiality=4, integrity=4, availability=5)
    derived = assessor.assets_from_findings(synthetic_findings, [bucket])
    assert [a.asset_id for a in derived] == [ROLE_ARN]  # 버킷은 인벤토리 자산과 중복 생성하지 않음

    assessments = {a.asset_id: a for a in assessor.assess_risks([bucket, *derived], synthetic_findings)}
    assert assessments['example-bucket'].total_findings == 5
    assert assessments['example-bucket'].risk_level == pi.RiskLevel.MEDIUM


def test_fail_findings_drive_asset_levels_and_summary(assessor, synthetic_findings):
    assets = assessor.assets_from_findings(synthetic_findings)
    assessments = assessor.assess_risks(assets, synthetic_findings)
    by_id = {a.asset_id: a for a in assessments}

    role, bucket = by_id[ROLE_ARN], by_id[BUCKET_ARN]
    assert (role.risk_level, role.risk_score, role.critical_count, role.high_count) == (
        pi.RiskLevel.CRITICAL, 40.0, 1, 1)
    # PASS/MANUAL 은 점수를 올리지 않음: FAIL Medium(8) + FAIL Low(3)
    assert (bucket.risk_level, bucket.risk_score, bucket.medium_count, bucket.low_count) == (
        pi.RiskLevel.MEDIUM, 11.0, 1, 1)

    report = pi.json.loads(assessor.generate_risk_report(assessments, assets, synthetic_findings)
                           .read_text(encoding='utf-8'))
    summary = report['summary']
    assert (summary['critical_risks'], summary['high_risks'], summary['medium_risks'],
            summary['low_risks']) == (1, 0, 1, 0)
    assert summary['average_risk_score'] == 25.5
    assert summary['fail_findings_by_severity'] == {'Critical': 1, 'High': 1, 'Medium': 1, 'Low': 1}
    assert summary['findings_by_status'] == {'FAIL': 4, 'PASS': 3, 'MANUAL': 1}


def test_pass_and_manual_only_asset_has_no_risk(assessor):
    findings = [assessor._parse_finding(ocsf_item(s, 'Critical', BUCKET_ARN, 'c')) for s in ('PASS', 'MANUAL')]
    (assessment,) = assessor.assess_risks(assessor.assets_from_findings(findings), findings)
    assert (assessment.risk_score, assessment.risk_level) == (0.0, pi.RiskLevel.INFO)


def test_full_assessment_merges_inventory_and_finding_assets(assessor, monkeypatch, tmp_path):
    ocsf = tmp_path / 'scan.ocsf.json'
    ocsf.write_text(pi.json.dumps(SYNTHETIC_OCSF), encoding='utf-8')
    monkeypatch.setattr(assessor, 'identify_assets', lambda: [])
    monkeypatch.setattr(assessor, 'run_prowler_scan', lambda **kwargs: ocsf)
    results = assessor.run_full_assessment()
    assert results['summary']['total_assets'] == 2
    assert results['summary']['critical_risks'] == 1


# --- CLI: --help / --dry-run 은 Prowler 를 실행하지 않음 ---

@pytest.fixture
def no_scan(monkeypatch):
    """subprocess.run 과 전체 평가 호출을 기록 (실제 실행 없음)"""
    calls: List[Any] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')

    monkeypatch.setattr(pi.subprocess, 'run', fake_run)
    monkeypatch.setattr(pi.ProwlerISMS2025, 'run_full_assessment',
                        lambda self, **kwargs: calls.append('full_assessment'))
    monkeypatch.setattr(pi.ProwlerISMS2025, 'identify_assets', lambda self: calls.append('identify_assets'))
    return calls


def test_help_prints_usage_without_scanning(no_scan, capsys):
    with pytest.raises(SystemExit) as exc:
        pi.main(['--help'])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for option in ('--profile', '--region', '--compliance', '--output-dir', '--dry-run'):
        assert option in out
    assert no_scan == []


def test_dry_run_prints_prowler_command_without_running(no_scan, capsys, tmp_path):
    pi.main(['--dry-run', '--profile', 'audit', '--region', 'us-east-1',
             '--compliance', 'iso27001_2022_aws', '--output-dir', str(tmp_path / 'out')])
    out = capsys.readouterr().out
    cmd = next(line for line in out.splitlines() if line.startswith('prowler ')).split()
    assert no_scan == []
    assert option_values(cmd, '-o') == [str(tmp_path / 'out')]
    assert option_values(cmd, '--compliance') == ['iso27001_2022_aws']
    assert option_values(cmd, '--profile') == ['audit']
    assert option_values(cmd, '--region') == ['us-east-1']


def test_default_output_dir_is_gitignored_output_not_cwd(monkeypatch):
    monkeypatch.delenv('ISMS_OUTPUT_DIR', raising=False)
    args = pi.build_parser(Config()).parse_args([])
    assert Path(args.output_dir) == Path(pi.__file__).resolve().parent / 'output'
    assert Path(args.output_dir) != Path.cwd()
    assert args.compliance == pi.ISMS_P_COMPLIANCE and args.dry_run is False


def test_script_help_exits_zero_and_writes_nothing(tmp_path):
    env = {**pi.os.environ, 'AWS_CONFIG_FILE': pi.os.devnull, 'AWS_SHARED_CREDENTIALS_FILE': pi.os.devnull,
           'AWS_EC2_METADATA_DISABLED': 'true'}
    result = subprocess.run([pi.sys.executable, str(Path(pi.__file__).resolve()), '--help'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert 'usage' in result.stdout and '--dry-run' in result.stdout
    assert list(tmp_path.iterdir()) == []


# --- 리뷰 반영: 매칭 정밀도, 다중/누락 리소스, WARNING, dry-run 부작용 ---

EC2_ARN = 'arn:aws:ec2:ap-northeast-2:123456789012:instance/i-0abc1234'


def resource(uid: str, name: str, rtype: str, group: str) -> Dict[str, Any]:
    return {'uid': uid, 'name': name, 'type': rtype, 'region': 'ap-northeast-2', 'group': {'name': group}}


def raw_item(status: str, severity: str, resources: List[Dict[str, Any]], check: str = 'c') -> Dict[str, Any]:
    return {'message': check, 'status_code': status, 'severity': severity, 'metadata': {'event_code': check},
            'finding_info': {'title': check}, 'resources': resources, 'remediation': {'desc': ''},
            'unmapped': {'compliance': {}}}


def inventory_asset(asset_id: str, asset_type: str, service: str) -> pi.Asset:
    return pi.Asset(asset_id=asset_id, asset_type=asset_type, asset_name=asset_id, service=service,
                    region='ap-northeast-2', importance=pi.AssetImportance.MEDIUM,
                    confidentiality=3, integrity=3, availability=3)


def test_same_name_different_type_does_not_merge(assessor):
    bucket = inventory_asset('example-role', 'S3', 's3')  # 역할과 이름이 같은 버킷
    finding = assessor._parse_finding(raw_item('FAIL', 'High', [
        resource(ROLE_ARN, 'example-role', 'AwsIamRole', 'iam')]))
    derived = assessor.assets_from_findings([finding], [bucket])
    assert [a.asset_id for a in derived] == [ROLE_ARN]
    by_id = {a.asset_id: a for a in assessor.assess_risks([bucket, *derived], [finding])}
    assert by_id['example-role'].total_findings == 0
    assert by_id[ROLE_ARN].total_findings == 1


def test_ec2_instance_arn_matches_inventory_id_without_duplicate(assessor):
    instance = inventory_asset('i-0abc1234', 'EC2', 'ec2')
    finding = assessor._parse_finding(raw_item('FAIL', 'Medium', [
        resource(EC2_ARN, 'web-server', 'AwsEc2Instance', 'ec2')]))
    assert assessor.assets_from_findings([finding], [instance]) == []
    (assessment,) = assessor.assess_risks([instance], [finding])
    assert (assessment.total_findings, assessment.risk_level) == (1, pi.RiskLevel.MEDIUM)


def test_multi_resource_finding_attaches_to_each_resource_once(assessor):
    finding = assessor._parse_finding(raw_item('FAIL', 'Low', [
        resource(BUCKET_ARN, 'example-bucket', 'AwsS3Bucket', 's3'),
        resource(ROLE_ARN, 'example-role', 'AwsIamRole', 'iam'),
        resource(BUCKET_ARN, 'example-bucket', 'AwsS3Bucket', 's3'),
    ]))
    assets = assessor.assets_from_findings([finding])
    assert {a.asset_id for a in assets} == {BUCKET_ARN, ROLE_ARN}
    by_id = {a.asset_id: a for a in assessor.assess_risks(assets, [finding])}
    assert by_id[BUCKET_ARN].total_findings == 1 and by_id[ROLE_ARN].total_findings == 1


def test_findings_without_resource_are_reported_as_unassigned(assessor):
    findings = [assessor._parse_finding(item) for item in (
        raw_item('FAIL', 'High', []),
        raw_item('PASS', 'Low', [resource('', '', 'Other', 'account')]),
        raw_item('FAIL', 'Medium', [resource(BUCKET_ARN, 'example-bucket', 'AwsS3Bucket', 's3')]),
    )]
    assets = assessor.assets_from_findings(findings)
    assessments = assessor.assess_risks(assets, findings)
    summary = pi.json.loads(assessor.generate_risk_report(assessments, assets, findings)
                            .read_text(encoding='utf-8'))['summary']
    assert summary['unassigned_findings'] == {
        'total': 2, 'by_status': {'FAIL': 1, 'PASS': 1},
        'fail_by_severity': {'Critical': 0, 'High': 1, 'Medium': 0, 'Low': 0}}
    assert summary['assigned_findings'] + summary['unassigned_findings']['total'] == len(findings)


def test_warning_status_does_not_raise_risk(assessor):
    assert assessor._determine_risk_level('WARNING', 'High') == pi.RiskLevel.INFO


def test_report_findings_include_resource_name_and_type(assessor, synthetic_findings):
    assets = assessor.assets_from_findings(synthetic_findings)
    report = pi.json.loads(assessor.generate_risk_report(
        assessor.assess_risks(assets, synthetic_findings), assets, synthetic_findings).read_text(encoding='utf-8'))
    first = report['findings'][0]
    assert (first['resource_name'], first['resource_type']) == ('example-role', 'AwsIamRole')


def test_dry_run_does_not_create_output_dir(no_scan, capsys, tmp_path):
    out_dir = tmp_path / 'not-created'
    pi.main(['--dry-run', '--output-dir', str(out_dir)])
    assert 'prowler aws' in capsys.readouterr().out
    assert not out_dir.exists()
