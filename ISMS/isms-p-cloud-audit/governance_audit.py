"""
멀티 계정 거버넌스 증적 수집기 (클라우드 시큐리티 9기 5주차)

AWS Organizations / Control Tower / CloudTrail 설정을 **읽기 전용**으로 조회해
ISMS-P 인증기준 항목에 매핑된 PASS / FAIL / UNKNOWN 증적(JSON + CSV)을 만듭니다.

수집 범위:
1. Organizations: 조직/기능 세트, OU 트리, 계정, 대상별 SCP·RCP 연결,
   CloudTrail 변조 차단 Deny(StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors)와
   ArnNotLike 등 예외 조건
2. CloudTrail: 조직 추적 여부, 다중 리전, 로깅 상태, 로그 파일 무결성 검증, KMS,
   (고급) 이벤트 선택기 기반 S3 데이터 이벤트(GetObject 등 읽기) 수집 범위
3. 중앙 로그 아카이브: 추적 버킷이 현재 계정 밖(별도 Log Archive 계정)에 있는지
4. Control Tower: 랜딩 존 상태/드리프트, 활성화된 컨트롤 수

설계 원칙:
- 쓰기 API를 호출하지 않습니다 (Describe/Get/List 만 사용).
- 단독 계정(AWSOrganizationsNotInUseException), 멤버 계정의 AccessDenied 등은
  예외로 중단하지 않고 UNKNOWN/FAIL 증적으로 기록합니다.
- 계정 ID, 자격 증명을 하드코딩하지 않습니다 (AWS SSO 프로필 기본값: twodragon).

ISMS-P 매핑은 KISA ISMS-P 인증기준(2023.10.5 고시 개정, 101개 항목)의 항목 번호/명칭을
따른 **참고용 매핑**이며, 공식 심사 판정을 대체하지 않습니다.
"""

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from utils.aws_clients import get_aws_clients  # noqa: E402
from utils.config import Config  # noqa: E402
from utils.exporters import DataExporter  # noqa: E402
from utils.logger import setup_logger  # noqa: E402

# 로거 설정
logger = setup_logger('isms.governance_audit')

PASS = 'PASS'
FAIL = 'FAIL'
UNKNOWN = 'UNKNOWN'

# CloudTrail 변조 차단 SCP가 반드시 Deny 해야 하는 액션
TAMPER_ACTIONS: Tuple[str, ...] = (
    'cloudtrail:StopLogging',
    'cloudtrail:DeleteTrail',
    'cloudtrail:UpdateTrail',
    'cloudtrail:PutEventSelectors',
)

# 예외(브레이크글래스/Control Tower 실행 역할 등)를 표현하는 조건 연산자
EXCEPTION_OPERATORS: Tuple[str, ...] = (
    'ArnNotLike', 'ArnNotEquals', 'StringNotLike', 'StringNotEquals',
)

# S3 읽기 계열 이벤트 이름 접두사 (eventName 필터가 읽기만 지정했는지 판별)
READ_EVENT_PREFIXES: Tuple[str, ...] = ('Get', 'Head', 'List')

# ISMS-P 인증기준 (2023.10.5 고시 개정 / 2023.11.23 안내서 기준 항목 번호·명칭)
ISMS_P_CRITERIA: Dict[str, str] = {
    '2.1.3': '정보자산 관리',
    '2.5.5': '특수 계정 및 권한 관리',
    '2.6.1': '네트워크 접근',
    '2.9.4': '로그 및 접속기록 관리',
    '2.9.5': '로그 및 접속기록 점검',
    '2.10.1': '보안시스템 운영',
    '2.11.3': '이상행위 분석 및 모니터링',
}

_ACCOUNT_ID_RE = re.compile(r'(?<!\d)\d{8}(\d{4})(?!\d)')


@dataclass
class GovernanceFinding:
    """거버넌스 점검 결과 1건"""
    check_id: str
    title: str
    status: str  # PASS, FAIL, UNKNOWN
    isms_p: List[str]
    resource: str
    detail: str
    collected_at: str
    evidence: Dict[str, Any] = field(default_factory=dict)


def utc_now() -> str:
    """ISO 8601 UTC 타임스탬프"""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def mask_account_ids(text: str) -> str:
    """12자리 계정 ID를 ``********1234`` 형태로 마스킹"""
    return _ACCOUNT_ID_RE.sub(lambda m: '********' + m.group(1), text)


def error_code(error: Exception) -> str:
    """boto 예외에서 오류 코드 추출"""
    if isinstance(error, ClientError):
        return error.response.get('Error', {}).get('Code', 'ClientError')
    return type(error).__name__


def _as_list(value: Any) -> List[Any]:
    """str/list/None 을 list 로 정규화"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _action_matches(pattern: str, action: str) -> bool:
    """IAM 액션 와일드카드 매칭 (대소문자 무시)"""
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def analyze_tamper_deny(policy_document: Dict[str, Any]) -> Dict[str, Any]:
    """
    SCP 문서에서 CloudTrail 변조 차단 Deny 문과 예외 조건 분석

    Args:
        policy_document: 파싱된 정책 JSON

    Returns:
        covered_actions / missing_actions / statements / exceptions 딕셔너리
    """
    covered = set()
    statements: List[str] = []
    exceptions: List[Dict[str, Any]] = []

    for index, stmt in enumerate(_as_list(policy_document.get('Statement'))):
        if not isinstance(stmt, dict) or stmt.get('Effect') != 'Deny':
            continue

        if 'NotAction' in stmt:
            excluded = _as_list(stmt.get('NotAction'))
            hits = {a for a in TAMPER_ACTIONS
                    if not any(_action_matches(p, a) for p in excluded)}
        else:
            patterns = _as_list(stmt.get('Action'))
            hits = {a for a in TAMPER_ACTIONS
                    if any(_action_matches(p, a) for p in patterns)}

        if not hits:
            continue

        covered |= hits
        statements.append(stmt.get('Sid') or f'Statement[{index}]')

        for operator, conditions in (stmt.get('Condition') or {}).items():
            base_operator = operator.replace('IfExists', '').split(':')[-1]
            if base_operator not in EXCEPTION_OPERATORS:
                continue
            for key, values in conditions.items():
                exceptions.append({
                    'sid': stmt.get('Sid') or f'Statement[{index}]',
                    'operator': operator,
                    'key': key,
                    'values': _as_list(values),
                })

    return {
        'covered_actions': sorted(covered),
        'missing_actions': sorted(set(TAMPER_ACTIONS) - covered),
        'statements': statements,
        'exceptions': exceptions,
    }


def _bucket_from_arn(value: str) -> str:
    """S3 ARN 값을 버킷 이름(또는 전체 '*')으로 변환"""
    if value.rstrip(':/') in ('arn:aws:s3', 'arn:aws:s3::'):
        return '*'
    remainder = value.split(':::', 1)[1] if ':::' in value else value
    bucket = remainder.split('/', 1)[0]
    return bucket or '*'


def analyze_event_selectors(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    GetEventSelectors 응답에서 S3 데이터 이벤트(읽기/쓰기) 수집 범위 분석

    Args:
        response: cloudtrail.get_event_selectors 응답

    Returns:
        s3_read / s3_write / read_buckets / write_buckets / excluded / selector_type
    """
    read_buckets: set = set()
    write_buckets: set = set()
    excluded: set = set()
    selector_type = 'none'

    for selector in response.get('EventSelectors') or []:
        selector_type = 'basic'
        rw_type = selector.get('ReadWriteType', 'All')
        for resource in selector.get('DataResources') or []:
            if resource.get('Type') != 'AWS::S3::Object':
                continue
            buckets = {_bucket_from_arn(v) for v in resource.get('Values') or []}
            if rw_type in ('All', 'ReadOnly'):
                read_buckets |= buckets
            if rw_type in ('All', 'WriteOnly'):
                write_buckets |= buckets

    for selector in response.get('AdvancedEventSelectors') or []:
        selector_type = 'advanced'
        fields: Dict[str, Dict[str, Any]] = {
            f.get('Field'): f for f in selector.get('FieldSelectors') or []
        }
        if 'Data' not in (fields.get('eventCategory') or {}).get('Equals', []):
            continue
        if 'AWS::S3::Object' not in (fields.get('resources.type') or {}).get('Equals', []):
            continue

        read_only = (fields.get('readOnly') or {}).get('Equals')
        captures_read = read_only is None or 'true' in read_only
        captures_write = read_only is None or 'false' in read_only

        event_name = fields.get('eventName') or {}
        if event_name.get('Equals'):
            names = event_name['Equals']
            if 'GetObject' not in names:
                captures_read = False
            if all(n.startswith(READ_EVENT_PREFIXES) for n in names):
                captures_write = False
        if 'GetObject' in (event_name.get('NotEquals') or []):
            captures_read = False

        arn_field = fields.get('resources.ARN') or {}
        values = (arn_field.get('StartsWith') or []) + (arn_field.get('Equals') or [])
        buckets = {_bucket_from_arn(v) for v in values} or {'*'}
        excluded |= {_bucket_from_arn(v) for v in arn_field.get('NotStartsWith') or []}

        if captures_read:
            read_buckets |= buckets
        if captures_write:
            write_buckets |= buckets

    return {
        'selector_type': selector_type,
        's3_read': bool(read_buckets),
        's3_write': bool(write_buckets),
        'read_buckets': sorted(read_buckets),
        'write_buckets': sorted(write_buckets),
        'excluded': sorted(excluded),
    }


class GovernanceAuditor:
    """Organizations / CloudTrail / Control Tower 거버넌스 증적 수집기"""

    def __init__(self, config: Config, clients: Optional[Dict[str, Any]] = None):
        """
        초기화

        Args:
            config: 설정 객체
            clients: 서비스명 → boto3 클라이언트 (테스트용 주입, 선택적)
        """
        self.config = config
        self._injected = clients or {}
        self._manager = None
        self.output_dir = Path(config.output_dir)
        self.collected_at = utc_now()
        self.errors: List[Dict[str, str]] = []

    def _client(self, service: str, region: Optional[str] = None):
        """주입된 클라이언트 우선, 없으면 공용 클라이언트 관리자 사용"""
        if service in self._injected:
            return self._injected[service]
        if self._manager is None:
            self._manager = get_aws_clients(
                region=self.config.aws_region, profile=self.config.aws_profile
            )
        return self._manager.get_client(service, region)

    def _record_error(self, api: str, error: Exception) -> str:
        """오류를 증적에 기록하고 코드 반환"""
        code = error_code(error)
        self.errors.append({'api': api, 'code': code})
        logger.warning(f"{api} 호출 실패 ({code}) - 해당 항목은 UNKNOWN 처리")
        return code

    @staticmethod
    def _paginate(client, operation: str, key: str, **kwargs) -> List[Dict[str, Any]]:
        """페이지네이터로 전체 결과 수집"""
        items: List[Dict[str, Any]] = []
        for page in client.get_paginator(operation).paginate(**kwargs):
            items.extend(page.get(key, []))
        return items

    # ------------------------------------------------------------------
    # 수집
    # ------------------------------------------------------------------
    def collect_identity(self) -> Dict[str, Any]:
        """호출자 계정 정보 수집"""
        try:
            identity = self._client('sts').get_caller_identity()
            return {'account_id': identity.get('Account'), 'arn': identity.get('Arn')}
        except (ClientError, BotoCoreError) as e:
            self._record_error('sts:GetCallerIdentity', e)
            return {'account_id': None, 'arn': None}

    def _collect_ou_tree(self, client, parent_id: str, depth: int = 0) -> Dict[str, Any]:
        """OU 트리 재귀 수집 (OU + 소속 계정)"""
        node: Dict[str, Any] = {'id': parent_id, 'accounts': [], 'children': []}
        accounts = self._paginate(client, 'list_accounts_for_parent', 'Accounts', ParentId=parent_id)
        node['accounts'] = [
            {'id': a.get('Id'), 'name': a.get('Name'), 'status': a.get('Status')}
            for a in accounts
        ]
        if depth >= 5:  # Organizations 최대 OU 중첩 깊이
            return node
        ous = self._paginate(
            client, 'list_organizational_units_for_parent', 'OrganizationalUnits', ParentId=parent_id
        )
        for ou in ous:
            child = self._collect_ou_tree(client, ou['Id'], depth + 1)
            child['name'] = ou.get('Name')
            child['arn'] = ou.get('Arn')
            node['children'].append(child)
        return node

    def _collect_policies(self, client, policy_type: str) -> List[Dict[str, Any]]:
        """정책 유형(SCP/RCP)별 정책, 본문, 연결 대상 수집"""
        policies = []
        summaries = self._paginate(client, 'list_policies', 'Policies', Filter=policy_type)
        for summary in summaries:
            policy_id = summary['Id']
            content: Dict[str, Any] = {}
            try:
                raw = client.describe_policy(PolicyId=policy_id)['Policy'].get('Content', '{}')
                content = json.loads(raw)
            except (ClientError, BotoCoreError) as e:
                self._record_error('organizations:DescribePolicy', e)
            except json.JSONDecodeError:
                logger.warning(f"정책 본문 파싱 실패: {summary.get('Name')}")
            targets = self._paginate(client, 'list_targets_for_policy', 'Targets', PolicyId=policy_id)
            policies.append({
                'id': policy_id,
                'name': summary.get('Name'),
                'aws_managed': summary.get('AwsManaged', False),
                'targets': [
                    {'id': t.get('TargetId'), 'name': t.get('Name'), 'type': t.get('Type')}
                    for t in targets
                ],
                'content': content,
                'tamper_analysis': analyze_tamper_deny(content) if content else None,
            })
        return policies

    def collect_organization(self) -> Dict[str, Any]:
        """Organizations 구조와 SCP/RCP 수집"""
        result: Dict[str, Any] = {'status': 'unknown'}
        client = self._client('organizations')

        try:
            org = client.describe_organization()['Organization']
        except ClientError as e:
            code = error_code(e)
            if code == 'AWSOrganizationsNotInUseException':
                logger.info("Organizations 미사용 단독 계정입니다")
                return {'status': 'standalone'}
            self._record_error('organizations:DescribeOrganization', e)
            result['error'] = code
            return result
        except BotoCoreError as e:
            result['error'] = self._record_error('organizations:DescribeOrganization', e)
            return result

        result.update({
            'status': 'member',
            'id': org.get('Id'),
            'feature_set': org.get('FeatureSet'),
            'management_account_id': org.get('MasterAccountId'),
        })

        try:
            roots = self._paginate(client, 'list_roots', 'Roots')
        except (ClientError, BotoCoreError) as e:
            # 멤버 계정은 조직 구조 조회 권한이 없음 (관리/위임 관리자 계정에서 실행 필요)
            result['error'] = self._record_error('organizations:ListRoots', e)
            return result

        result['status'] = 'management_or_delegated'
        root = roots[0] if roots else {}
        enabled_types = [
            p.get('Type') for p in root.get('PolicyTypes', []) if p.get('Status') == 'ENABLED'
        ]
        result['root'] = {'id': root.get('Id'), 'enabled_policy_types': enabled_types}

        try:
            result['tree'] = self._collect_ou_tree(client, root['Id']) if root else None
        except (ClientError, BotoCoreError) as e:
            self._record_error('organizations:ListOrganizationalUnitsForParent', e)
            result['tree'] = None

        for policy_type, key in (('SERVICE_CONTROL_POLICY', 'scps'),
                                 ('RESOURCE_CONTROL_POLICY', 'rcps')):
            if policy_type not in enabled_types:
                result[key] = []
                continue
            try:
                result[key] = self._collect_policies(client, policy_type)
            except (ClientError, BotoCoreError) as e:
                self._record_error(f'organizations:ListPolicies({policy_type})', e)
                result[key] = None
        return result

    def collect_cloudtrail(self) -> Dict[str, Any]:
        """추적 목록, 로깅 상태, 이벤트 선택기 수집"""
        client = self._client('cloudtrail')
        try:
            trails = client.describe_trails(includeShadowTrails=True).get('trailList', [])
        except (ClientError, BotoCoreError) as e:
            return {'error': self._record_error('cloudtrail:DescribeTrails', e), 'trails': None}

        collected = []
        for trail in trails:
            arn = trail.get('TrailARN') or trail.get('Name')
            home_region = trail.get('HomeRegion')
            regional = self._client('cloudtrail', home_region)
            item = {
                'name': trail.get('Name'),
                'arn': arn,
                'home_region': home_region,
                'is_organization_trail': trail.get('IsOrganizationTrail', False),
                'is_multi_region': trail.get('IsMultiRegionTrail', False),
                'log_file_validation': trail.get('LogFileValidationEnabled', False),
                'kms_key_id': trail.get('KmsKeyId'),
                's3_bucket': trail.get('S3BucketName'),
                'cloudwatch_logs_group': trail.get('CloudWatchLogsLogGroupArn'),
                'is_logging': None,
                'data_events': None,
            }
            try:
                status = regional.get_trail_status(Name=arn)
                item['is_logging'] = status.get('IsLogging')
                item['latest_delivery_error'] = status.get('LatestDeliveryError')
            except (ClientError, BotoCoreError) as e:
                self._record_error('cloudtrail:GetTrailStatus', e)
            try:
                item['data_events'] = analyze_event_selectors(
                    regional.get_event_selectors(TrailName=arn)
                )
            except (ClientError, BotoCoreError) as e:
                self._record_error('cloudtrail:GetEventSelectors', e)
            collected.append(item)
        return {'trails': collected}

    def collect_own_buckets(self) -> Optional[List[str]]:
        """현재 계정 소유 버킷 목록 (중앙 로그 아카이브 판별용)"""
        try:
            buckets = self._client('s3').list_buckets().get('Buckets', [])
            return [b['Name'] for b in buckets]
        except (ClientError, BotoCoreError) as e:
            self._record_error('s3:ListAllMyBuckets', e)
            return None

    def collect_control_tower(self) -> Dict[str, Any]:
        """Control Tower 랜딩 존 및 활성화된 컨트롤 수집"""
        client = self._client('controltower')
        try:
            zones = self._paginate(client, 'list_landing_zones', 'landingZones')
        except (ClientError, BotoCoreError) as e:
            return {'error': self._record_error('controltower:ListLandingZones', e)}

        if not zones:
            return {'landing_zone': None}

        result: Dict[str, Any] = {'landing_zone': {'arn': zones[0].get('arn')}}
        try:
            lz = client.get_landing_zone(landingZoneIdentifier=zones[0]['arn'])['landingZone']
            result['landing_zone'].update({
                'version': lz.get('version'),
                'latest_available_version': lz.get('latestAvailableVersion'),
                'status': lz.get('status'),
                'drift_status': (lz.get('driftStatus') or {}).get('status'),
            })
        except (ClientError, BotoCoreError) as e:
            self._record_error('controltower:GetLandingZone', e)
        try:
            controls = self._paginate(client, 'list_enabled_controls', 'enabledControls')
            result['enabled_controls'] = len(controls)
        except (ClientError, BotoCoreError) as e:
            self._record_error('controltower:ListEnabledControls', e)
            result['enabled_controls'] = None
        return result

    # ------------------------------------------------------------------
    # 평가
    # ------------------------------------------------------------------
    def _finding(self, check_id: str, title: str, status: str, isms_p: List[str],
                 resource: str, detail: str, evidence: Optional[Dict[str, Any]] = None
                 ) -> GovernanceFinding:
        return GovernanceFinding(
            check_id=check_id, title=title, status=status, isms_p=isms_p,
            resource=resource, detail=detail, collected_at=self.collected_at,
            evidence=evidence or {},
        )

    def evaluate_organization(self, org: Dict[str, Any]) -> List[GovernanceFinding]:
        """Organizations / SCP / RCP 평가"""
        findings = []
        status = org.get('status')

        if status == 'standalone':
            detail = 'Organizations 미사용 단독 계정 - SCP/RCP 가드레일 적용 불가'
            for check_id, title, isms in (
                ('GOV-ORG-01', 'Organizations 모든 기능(ALL) 활성화', ['2.1.3', '2.5.5']),
                ('GOV-ORG-02', '사용자 정의 SCP 연결', ['2.5.5']),
                ('GOV-ORG-03', 'CloudTrail 변조 차단 SCP', ['2.9.4', '2.10.1']),
                ('GOV-ORG-04', '사용자 정의 RCP 연결', ['2.5.5', '2.6.1']),
            ):
                findings.append(self._finding(check_id, title, FAIL, isms, 'organization', detail))
            return findings

        feature_set = org.get('feature_set')
        if feature_set is None:
            org_status = UNKNOWN
        else:
            org_status = PASS if feature_set == 'ALL' else FAIL
        findings.append(self._finding(
            'GOV-ORG-01', 'Organizations 모든 기능(ALL) 활성화', org_status, ['2.1.3', '2.5.5'],
            org.get('id') or 'organization',
            f"FeatureSet={feature_set}" if feature_set else f"조회 실패: {org.get('error')}",
        ))

        scps = org.get('scps')
        rcps = org.get('rcps')
        no_scope = 'scps' not in org  # 멤버 계정 등 조직 구조 조회 불가

        # GOV-ORG-02: 사용자 정의 SCP 연결
        if no_scope or scps is None:
            findings.append(self._finding(
                'GOV-ORG-02', '사용자 정의 SCP 연결', UNKNOWN, ['2.5.5'], 'organization',
                '관리 계정 또는 위임 관리자 계정에서 실행 필요 (ListPolicies 권한)',
            ))
        else:
            custom = [p for p in scps if not p['aws_managed'] and p['targets']]
            findings.append(self._finding(
                'GOV-ORG-02', '사용자 정의 SCP 연결', PASS if custom else FAIL, ['2.5.5'],
                'organization',
                f"연결된 사용자 정의 SCP {len(custom)}개: " + ', '.join(p['name'] for p in custom)
                if custom else 'FullAWSAccess 외 연결된 SCP 없음',
                {'attachments': self._attachments(scps)},
            ))

        # GOV-ORG-03: CloudTrail 변조 차단 SCP
        findings.append(self._evaluate_tamper(scps if not no_scope else None))

        # GOV-ORG-04: 사용자 정의 RCP 연결
        if no_scope or rcps is None:
            findings.append(self._finding(
                'GOV-ORG-04', '사용자 정의 RCP 연결', UNKNOWN, ['2.5.5', '2.6.1'], 'organization',
                '관리 계정 또는 위임 관리자 계정에서 실행 필요 (ListPolicies 권한)',
            ))
        else:
            enabled = 'RESOURCE_CONTROL_POLICY' in org.get('root', {}).get('enabled_policy_types', [])
            custom = [p for p in rcps if not p['aws_managed'] and p['targets']]
            if custom:
                detail = f"연결된 사용자 정의 RCP {len(custom)}개: " + ', '.join(p['name'] for p in custom)
            elif enabled:
                detail = 'RCP 유형은 활성화됐으나 RCPFullAWSAccess 외 연결된 RCP 없음'
            else:
                detail = 'RCP 정책 유형 비활성화'
            findings.append(self._finding(
                'GOV-ORG-04', '사용자 정의 RCP 연결', PASS if custom else FAIL, ['2.5.5', '2.6.1'],
                'organization', detail, {'attachments': self._attachments(rcps)},
            ))
        return findings

    @staticmethod
    def _attachments(policies: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """대상(Root/OU/계정)별 연결 정책 이름"""
        by_target: Dict[str, List[str]] = {}
        for policy in policies:
            for target in policy['targets']:
                label = f"{target['type']}:{target['name'] or target['id']}"
                by_target.setdefault(label, []).append(policy['name'])
        return by_target

    def _evaluate_tamper(self, scps: Optional[List[Dict[str, Any]]]) -> GovernanceFinding:
        """CloudTrail 변조 차단 Deny 존재 여부 평가"""
        title = 'CloudTrail 변조 차단 SCP (StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors)'
        isms = ['2.9.4', '2.10.1']
        if scps is None:
            return self._finding(
                'GOV-ORG-03', title, UNKNOWN, isms, 'organization',
                'SCP 조회 불가 - 관리 계정 또는 위임 관리자 계정에서 실행 필요',
            )

        covered = set()
        exceptions: List[Dict[str, Any]] = []
        matched: List[str] = []
        unattached: List[str] = []
        for policy in scps:
            analysis = policy.get('tamper_analysis')
            if not analysis or not analysis['covered_actions']:
                continue
            if not policy['targets']:
                unattached.append(policy['name'])
                continue
            matched.append(policy['name'])
            covered |= set(analysis['covered_actions'])
            exceptions.extend(
                dict(e, policy=policy['name']) for e in analysis['exceptions']
            )

        missing = sorted(set(TAMPER_ACTIONS) - covered)
        if matched and not missing:
            status = PASS
            detail = f"Deny 정책: {', '.join(matched)}"
        elif matched:
            status = FAIL
            detail = f"Deny 정책 {', '.join(matched)} - 누락 액션: {', '.join(missing)}"
        else:
            status = FAIL
            detail = '변조 차단 Deny SCP 없음'
        if unattached:
            detail += f" / 미연결 정책: {', '.join(unattached)}"
        if exceptions:
            detail += ' / 예외: ' + '; '.join(
                f"{e['operator']} {e['key']}={e['values']}" for e in exceptions
            )
        return self._finding(
            'GOV-ORG-03', title, status, isms, 'organization', detail,
            {'covered_actions': sorted(covered), 'missing_actions': missing,
             'policies': matched, 'unattached_policies': unattached, 'exceptions': exceptions},
        )

    def evaluate_cloudtrail(self, cloudtrail: Dict[str, Any],
                            own_buckets: Optional[List[str]]) -> List[GovernanceFinding]:
        """CloudTrail 및 중앙 로그 아카이브 평가"""
        trails = cloudtrail.get('trails')
        checks = (
            ('GOV-CT-01', '조직 추적(Organization trail) 로깅', ['2.9.4', '2.11.3']),
            ('GOV-CT-02', '다중 리전 추적', ['2.9.4']),
            ('GOV-CT-03', '로그 파일 무결성 검증', ['2.9.4']),
            ('GOV-CT-04', '추적 로그 KMS 암호화', ['2.9.4', '2.10.1']),
            ('GOV-CT-05', 'S3 데이터 이벤트(GetObject 등 읽기) 수집', ['2.9.4', '2.11.3']),
            ('GOV-CT-06', 'CloudWatch Logs 연동 (SIEM 수집 경로)', ['2.9.5', '2.11.3']),
            ('GOV-LOG-01', '중앙 로그 아카이브 (별도 계정 버킷)', ['2.9.4']),
        )
        if trails is None:
            return [self._finding(c, t, UNKNOWN, i, 'cloudtrail',
                                  f"DescribeTrails 실패: {cloudtrail.get('error')}")
                    for c, t, i in checks]

        logging_trails = [t for t in trails if t.get('is_logging')]
        org_logging = [t for t in logging_trails if t['is_organization_trail']]
        names = lambda items: ', '.join(t['name'] for t in items) or '-'  # noqa: E731
        findings = []

        # GOV-CT-01
        if org_logging:
            status, detail = PASS, f"로깅 중인 조직 추적: {names(org_logging)}"
        elif any(t.get('is_logging') is None for t in trails):
            status, detail = UNKNOWN, 'GetTrailStatus 조회 실패 추적 존재'
        else:
            status = FAIL
            detail = f"로깅 중인 조직 추적 없음 (계정 추적 로깅 {len(logging_trails)}개)"
        findings.append(self._finding(*checks[0][:2], status, checks[0][2], names(trails), detail))

        def all_logging(check, predicate, ok_msg, fail_msg):
            check_id, title, isms = check
            if not logging_trails:
                return self._finding(check_id, title, FAIL, isms, 'cloudtrail', '로깅 중인 추적 없음')
            bad = [t for t in logging_trails if not predicate(t)]
            return self._finding(
                check_id, title, FAIL if bad else PASS, isms, names(logging_trails),
                f"{fail_msg}: {names(bad)}" if bad else ok_msg,
            )

        # GOV-CT-02
        multi = [t for t in logging_trails if t['is_multi_region']]
        findings.append(self._finding(
            *checks[1][:2], PASS if multi else FAIL, checks[1][2], names(logging_trails),
            f"다중 리전 추적: {names(multi)}" if multi else '로깅 중인 다중 리전 추적 없음',
        ))
        # GOV-CT-03 / GOV-CT-04
        findings.append(all_logging(checks[2], lambda t: t['log_file_validation'],
                                    '모든 로깅 추적에 무결성 검증 활성화', '무결성 검증 비활성'))
        findings.append(all_logging(checks[3], lambda t: t['kms_key_id'],
                                    '모든 로깅 추적 SSE-KMS 암호화', 'KMS 미설정'))

        # GOV-CT-05
        reading = [t for t in logging_trails if (t.get('data_events') or {}).get('s3_read')]
        if reading:
            scope = {t['name']: t['data_events']['read_buckets'] for t in reading}
            status = PASS
            detail = 'S3 읽기 데이터 이벤트 수집: ' + '; '.join(
                f"{k}→{','.join(v)}" for k, v in scope.items())
        elif any(t.get('data_events') is None for t in logging_trails):
            status, detail, scope = UNKNOWN, 'GetEventSelectors 조회 실패 추적 존재', {}
        else:
            status, detail, scope = FAIL, 'S3 읽기(GetObject) 데이터 이벤트 미수집', {}
        findings.append(self._finding(*checks[4][:2], status, checks[4][2],
                                      names(logging_trails), detail, {'read_scope': scope}))

        # GOV-CT-06: CloudWatch Logs 미연동이어도 S3 기반 SIEM 수집일 수 있어 UNKNOWN
        cwl = [t for t in logging_trails if t.get('cloudwatch_logs_group')]
        findings.append(self._finding(
            *checks[5][:2], PASS if cwl else UNKNOWN, checks[5][2], names(logging_trails),
            f"CloudWatch Logs 연동 추적: {names(cwl)}" if cwl else
            'CloudWatch Logs 미연동 - S3 기반 SIEM(Security Lake, OpenSearch 등) 수집 여부 수동 확인',
        ))

        # GOV-LOG-01: 조직 추적 버킷이 현재 계정 버킷 목록에 없으면 별도(Log Archive) 계정
        primary = org_logging or logging_trails
        if not primary:
            status, detail = FAIL, '로깅 중인 추적 없음'
        elif own_buckets is None:
            status, detail = UNKNOWN, 's3:ListAllMyBuckets 권한 없음 - 버킷 소유 계정 판별 불가'
        else:
            local = [t for t in primary if t.get('s3_bucket') in own_buckets]
            status = FAIL if local else PASS
            detail = (f"추적 버킷이 현재 계정에 존재: {', '.join(t['s3_bucket'] for t in local)}"
                      if local else '추적 버킷이 별도 계정(Log Archive)에 위치')
        findings.append(self._finding(*checks[6][:2], status, checks[6][2],
                                      ', '.join(sorted({t.get('s3_bucket') or '-' for t in primary})) or '-',
                                      detail))
        return findings

    def evaluate_control_tower(self, control_tower: Dict[str, Any]) -> List[GovernanceFinding]:
        """Control Tower 랜딩 존 평가"""
        check_id, title, isms = 'GOV-CTW-01', 'Control Tower 랜딩 존 (드리프트 없음)', ['2.10.1']
        if 'error' in control_tower:
            return [self._finding(check_id, title, UNKNOWN, isms, 'controltower',
                                  f"조회 실패: {control_tower['error']} (관리 계정·홈 리전에서 실행)")]
        lz = control_tower.get('landing_zone')
        if not lz:
            return [self._finding(check_id, title, FAIL, isms, 'controltower',
                                  '랜딩 존 없음 (홈 리전이 다르면 --region 으로 재실행)')]
        drift = lz.get('drift_status')
        ok = lz.get('status') == 'ACTIVE' and drift == 'IN_SYNC'
        status = PASS if ok else (UNKNOWN if lz.get('status') is None else FAIL)
        detail = (f"status={lz.get('status')}, drift={drift}, version={lz.get('version')}, "
                  f"enabled_controls={control_tower.get('enabled_controls')}")
        return [self._finding(check_id, title, status, isms, lz.get('arn') or 'controltower',
                              detail, {'landing_zone': lz})]

    # ------------------------------------------------------------------
    # 실행 / 내보내기
    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """전체 수집·평가 실행 후 보고서 딕셔너리 반환"""
        logger.info("=== 거버넌스 증적 수집 시작 (읽기 전용) ===")
        identity = self.collect_identity()
        organization = self.collect_organization()
        cloudtrail = self.collect_cloudtrail()
        own_buckets = self.collect_own_buckets()
        control_tower = self.collect_control_tower()

        findings = (
            self.evaluate_organization(organization)
            + self.evaluate_cloudtrail(cloudtrail, own_buckets)
            + self.evaluate_control_tower(control_tower)
        )
        summary = {s: sum(1 for f in findings if f.status == s) for s in (PASS, FAIL, UNKNOWN)}

        report = {
            'report_metadata': {
                'report_type': 'ISMS-P Multi-account Governance Evidence',
                'collected_at': self.collected_at,
                'region': self.config.aws_region,
                'profile': self.config.aws_profile,
                'caller': identity,
                'isms_p_reference': 'KISA ISMS-P 인증기준 (2023.10.5 고시 개정, 101개 항목) - 참고 매핑',
            },
            'summary': summary,
            'findings': [asdict(f) for f in findings],
            'raw': {
                'organization': organization,
                'cloudtrail': cloudtrail,
                'control_tower': control_tower,
            },
            'errors': self.errors,
        }
        # datetime 등 JSON 비호환 값을 문자열로 정규화
        return json.loads(json.dumps(report, default=str))

    def export(self, report: Dict[str, Any], mask: bool = False) -> Tuple[Path, Path]:
        """
        JSON(전체 증적) + CSV(항목별 판정) 내보내기

        Args:
            report: run() 결과
            mask: True 면 계정 ID 마스킹

        Returns:
            (JSON 경로, CSV 경로)
        """
        if mask:
            report = json.loads(mask_account_ids(json.dumps(report, ensure_ascii=False)))
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = self.output_dir / f'governance_evidence_{stamp}.json'
        csv_path = self.output_dir / f'governance_evidence_{stamp}.csv'

        DataExporter.export_to_json(report, str(json_path))
        headers = ['collected_at', 'check_id', 'status', 'isms_p', 'isms_p_title',
                   'title', 'resource', 'detail']
        rows = [[
            f['collected_at'], f['check_id'], f['status'], ' / '.join(f['isms_p']),
            ' / '.join(ISMS_P_CRITERIA.get(i, '') for i in f['isms_p']),
            f['title'], f['resource'], f['detail'],
        ] for f in report['findings']]
        DataExporter.export_to_csv(rows, headers, str(csv_path))
        return json_path, csv_path


def main() -> None:
    """메인 함수"""
    config = Config.from_env()
    parser = argparse.ArgumentParser(description='ISMS-P 멀티 계정 거버넌스 증적 수집 (읽기 전용)')
    parser.add_argument('--profile', default=config.aws_profile, help='AWS 프로필 (기본: twodragon)')
    parser.add_argument('--region', default=config.aws_region,
                        help='리전 (Control Tower 홈 리전 권장, 기본: ap-northeast-2)')
    parser.add_argument('--output-dir', default=config.output_dir, help='출력 디렉토리')
    parser.add_argument('--mask-account-ids', action='store_true',
                        help='출력 파일의 12자리 계정 ID 마스킹 (공유용)')
    args = parser.parse_args()

    config.aws_profile = args.profile
    config.aws_region = args.region
    config.output_dir = args.output_dir

    try:
        auditor = GovernanceAuditor(config)
        report = auditor.run()
        if report['report_metadata']['caller']['account_id'] is None:
            # 자격 증명 자체가 없으면 전 항목 UNKNOWN 증적이 되므로 저장하지 않음
            logger.error(f"자격 증명 확인 실패 - aws sso login --profile {config.aws_profile} 후 재실행")
            sys.exit(1)
        json_path, csv_path = auditor.export(report, mask=args.mask_account_ids)
    except (BotoCoreError, ClientError) as e:
        logger.error(f"AWS 호출 실패: {e} (aws sso login --profile {config.aws_profile} 확인)")
        sys.exit(1)

    print("\n=== 거버넌스 증적 요약 ===")
    for finding in report['findings']:
        print(mask_account_ids(
            f"[{finding['status']:<7}] {finding['check_id']:<10} "
            f"{'/'.join(finding['isms_p']):<14} {finding['title']}"
        ))
    print(f"\nPASS={report['summary'][PASS]} FAIL={report['summary'][FAIL]} "
          f"UNKNOWN={report['summary'][UNKNOWN]}")
    print(f"JSON: {json_path}\nCSV:  {csv_path}")


if __name__ == '__main__':
    main()
