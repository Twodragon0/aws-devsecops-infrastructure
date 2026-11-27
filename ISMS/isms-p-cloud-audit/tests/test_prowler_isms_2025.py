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
    assert finding.risk_level == pi.RiskLevel.CRITICAL


def test_parse_legacy_finding_unchanged(assessor):
    finding = assessor._parse_finding({'CheckID': 'x', 'Status': 'PASS', 'Severity': 'low',
                                       'ServiceName': 's3', 'Region': 'ap-northeast-2',
                                       'ResourceId': 'b', 'Message': 'ok', 'Remediation': 'none'})
    assert (finding.check_id, finding.status, finding.service, finding.remediation) == ('x', 'PASS', 's3', 'none')
