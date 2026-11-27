"""
ISMS-P 2025 가이드 기반 Prowler 자산 식별 및 위험 관리 시스템

이 스크립트는 ISMS-P 2025 최신 가이드에 따라 다음을 수행합니다:
1. AWS 자산 자동 식별
2. 보안 취약점 점검 및 위험 평가
3. 위험 등급 부여 및 우선순위 관리
4. 위험 관리 보고서 생성
5. 지속적인 모니터링 및 알림

주요 특징:
- 클라우드 환경 보안 강화 점검
- AI/머신러닝 데이터 처리 보안 점검
- 자산 중요도 평가 (CIA 기준)
- 위험 등급 자동 부여
- 개선 조치 추적
"""

import sys
import json
import os
import shlex
import argparse
import subprocess
from collections import Counter
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Sequence, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.aws_clients import get_aws_clients
from utils.config import Config
from utils.logger import setup_logger
from utils.exceptions import AssetCollectionError
from botocore.exceptions import ClientError

# 로거 설정
logger = setup_logger('isms.prowler_isms_2025')

# Prowler 5.x 기본 ISMS-P 컴플라이언스 프레임워크 (prowler aws --list-compliance 로 확인)
ISMS_P_COMPLIANCE = 'kisa_isms_p_2023_korean_aws'

# 기존 output_format 인자 → Prowler 5.x -M 값, 결과 파일 확장자
PROWLER_OUTPUT_FORMATS = {'json': 'json-ocsf', 'json-ocsf': 'json-ocsf', 'csv': 'csv',
                          'html': 'html', 'json-asff': 'json-asff'}
PROWLER_FILE_SUFFIXES = {'json-ocsf': '.ocsf.json', 'csv': '.csv', 'html': '.html',
                         'json-asff': '.asff.json'}

# 기본 출력 디렉토리: 스크립트 옆 output/ (.gitignore 대상, 현재 작업 디렉토리에 결과를 남기지 않음)
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / 'output'


class RiskLevel(Enum):
    """위험 등급"""
    CRITICAL = "Critical"  # 즉시 조치 필요
    HIGH = "High"  # 우선 조치 필요
    MEDIUM = "Medium"  # 계획적 조치 필요
    LOW = "Low"  # 모니터링 필요
    INFO = "Info"  # 정보성


# 낮음 → 높음 순서 (자산 위험 등급 비교용)
RISK_LEVEL_ORDER = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


class AssetImportance(Enum):
    """자산 중요도 (CIA 기준)"""
    CRITICAL = "Critical"  # 기밀성, 무결성, 가용성 모두 높음
    HIGH = "High"  # 2개 이상 높음
    MEDIUM = "Medium"  # 1개 높음
    LOW = "Low"  # 모두 낮음


@dataclass
class SecurityFinding:
    """보안 발견 사항"""
    check_id: str
    check_title: str
    status: str  # PASS, FAIL, WARNING
    risk_level: RiskLevel
    severity: str
    service: str
    region: str
    resource_id: str
    description: str
    remediation: str
    compliance_frameworks: List[str]
    asset_importance: Optional[AssetImportance] = None
    detected_at: Optional[str] = None
    remediated_at: Optional[str] = None
    resource_name: str = ''
    resource_type: str = ''


@dataclass
class Asset:
    """정보 자산"""
    asset_id: str
    asset_type: str
    asset_name: str
    service: str
    region: str
    importance: AssetImportance
    confidentiality: int  # 1-5
    integrity: int  # 1-5
    availability: int  # 1-5
    owner: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    created_at: Optional[str] = None
    last_audited: Optional[str] = None


@dataclass
class RiskAssessment:
    """위험 평가"""
    asset_id: str
    asset_name: str
    risk_score: float  # 0-100
    risk_level: RiskLevel
    findings: List[SecurityFinding]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    assessed_at: str


class ProwlerISMS2025:
    """ISMS-P 2025 가이드 기반 Prowler 통합 클래스"""
    
    def __init__(self, config: Config):
        """
        초기화
        
        Args:
            config: 설정 객체
        """
        self.config = config
        self.clients = get_aws_clients(region=config.aws_region, profile=config.aws_profile)
        self.output_dir = Path(config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 위험 평가 기준 (ISMS-P 2025)
        self.risk_thresholds = {
            RiskLevel.CRITICAL: 80,
            RiskLevel.HIGH: 60,
            RiskLevel.MEDIUM: 40,
            RiskLevel.LOW: 20
        }
    
    def check_prowler_installed(self) -> bool:
        """Prowler 설치 여부 확인"""
        try:
            result = subprocess.run(
                ['prowler', '-v'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Prowler 버전 확인: {result.stdout.strip()}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.error("Prowler가 설치되지 않았습니다. 'pip install prowler' 실행 필요")
            return False
    
    def run_prowler_scan(
        self,
        output_format: str = 'json',
        compliance_framework: Optional[str] = None,
        services: Optional[List[str]] = None
    ) -> Path:
        """
        Prowler 5.x 스캔 실행

        Args:
            output_format: 출력 형식 (json → json-ocsf, csv, html, json-asff). CSV 는 항상 함께 저장
            compliance_framework: Prowler 컴플라이언스 이름 (예: kisa_isms_p_2023_korean_aws,
                iso27001_2022_aws). 결과 CSV 는 output_dir/compliance/ 에 저장
            services: 점검할 서비스 목록 (None이면 전체, compliance_framework 와 동시 사용 불가)

        Returns:
            출력 파일 경로 (output_format 형식)
        """
        if not self.check_prowler_installed():
            raise AssetCollectionError("Prowler가 설치되지 않았습니다")

        cmd, output_file = self.build_prowler_command(output_format, compliance_framework, services)
        logger.info(f"Prowler 스캔 시작: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1시간 타임아웃
                env={**os.environ, 'AWS_PROFILE': self.config.aws_profile} if self.config.aws_profile else os.environ
            )

            if result.returncode == 0:
                logger.info(f"Prowler 스캔 완료: {output_file}")
                return output_file
            else:
                logger.error(f"Prowler 스캔 실패: {result.stderr}")
                raise AssetCollectionError(f"Prowler 스캔 실패: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error("Prowler 스캔 타임아웃")
            raise AssetCollectionError("Prowler 스캔이 시간 초과되었습니다")

    def build_prowler_command(
        self,
        output_format: str = 'json',
        compliance_framework: Optional[str] = None,
        services: Optional[List[str]] = None
    ) -> Tuple[List[str], Path]:
        """Prowler 5.x 명령어와 예상 출력 파일 경로 구성 (실행하지 않음, --dry-run 에서도 사용)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_name = f"prowler_scan_{timestamp}"
        prowler_format = PROWLER_OUTPUT_FORMATS.get(output_format, output_format)
        suffix = PROWLER_FILE_SUFFIXES.get(prowler_format, '.' + prowler_format)
        output_file = self.output_dir / f"{output_name}{suffix}"
        formats = ['csv'] if prowler_format == 'csv' else ['csv', prowler_format]

        # Prowler 5.x 명령어 구성 (-M 출력 형식, -o 출력 디렉토리, -F 파일 이름)
        # 실패 항목이 있어도 종료 코드 3 대신 0 을 받도록 --ignore-exit-code-3 사용
        cmd = ['prowler', 'aws', '-M', *formats, '-o', str(self.output_dir), '-F', output_name,
               '--ignore-exit-code-3']
        
        # AWS profile 지정
        if self.config.aws_profile:
            cmd.extend(['--profile', self.config.aws_profile])
            logger.info(f"AWS Profile 사용: {self.config.aws_profile}")
        
        # AWS 리전 지정
        if self.config.aws_region:
            cmd.extend(['--region', self.config.aws_region])
        
        # 컴플라이언스 프레임워크 지정 (Prowler 5.x: --compliance, -c 는 체크 지정)
        if compliance_framework:
            cmd.extend(['--compliance', compliance_framework])
            if services:
                logger.warning("Prowler 5.x 에서 --compliance 와 -s 는 함께 쓸 수 없어 서비스 필터를 무시합니다")
        elif services:
            # 서비스 필터 (공백으로 구분된 여러 값)
            cmd.extend(['-s', *services])
        
        # ISMS-P 2025 관련 추가 옵션
        # 클라우드 환경 보안 강화 점검
        cmd.extend(['--verbose', '--log-level', 'INFO'])
        return cmd, output_file

    def parse_prowler_results(self, json_file: Path) -> List[SecurityFinding]:
        """
        Prowler JSON 결과 파싱
        
        Args:
            json_file: Prowler JSON 출력 파일
        
        Returns:
            보안 발견 사항 리스트
        """
        logger.info(f"Prowler 결과 파싱: {json_file}")
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            findings = []
            
            # Prowler 출력 형식에 따라 파싱
            if isinstance(data, list):
                for item in data:
                    finding = self._parse_finding(item)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict):
                # 다른 형식 처리
                if 'findings' in data:
                    for item in data['findings']:
                        finding = self._parse_finding(item)
                        if finding:
                            findings.append(finding)
            
            logger.info(f"총 {len(findings)}개의 보안 발견 사항 파싱 완료")
            return findings
        
        except Exception as e:
            logger.error(f"Prowler 결과 파싱 실패: {e}")
            raise AssetCollectionError(f"결과 파싱 실패: {e}")
    
    def _parse_finding(self, item: Dict[str, Any]) -> Optional[SecurityFinding]:
        """개별 발견 사항 파싱"""
        try:
            # Prowler 출력 형식에 맞춰 필드 매핑
            # Prowler 5.x json-ocsf 형식은 metadata/finding_info/resources 에 값이 있음
            if 'status_code' in item:
                return self._parse_ocsf_finding(item)

            check_id = item.get('CheckID', item.get('check_id', ''))
            status = item.get('Status', item.get('status', 'UNKNOWN'))
            severity = item.get('Severity', item.get('severity', 'unknown'))
            
            # 위험 등급 결정
            risk_level = self._determine_risk_level(status, severity)
            
            finding = SecurityFinding(
                check_id=check_id,
                check_title=item.get('CheckTitle', item.get('check_title', '')),
                status=status,
                risk_level=risk_level,
                severity=severity,
                service=item.get('ServiceName', item.get('service', '')),
                region=item.get('Region', item.get('region', '')),
                resource_id=item.get('ResourceId', item.get('resource_id', '')),
                description=item.get('Message', item.get('description', '')),
                remediation=item.get('Remediation', item.get('remediation', '')),
                compliance_frameworks=item.get('Compliance', item.get('compliance', [])),
                detected_at=datetime.now().isoformat()
            )
            
            return finding
        
        except Exception as e:
            logger.warning(f"발견 사항 파싱 실패: {e}")
            return None
    
    def _parse_ocsf_finding(self, item: Dict[str, Any]) -> SecurityFinding:
        """Prowler 5.x json-ocsf 발견 사항 파싱"""
        resource = (item.get('resources') or [{}])[0]
        remediation = item.get('remediation') or {}
        status = item.get('status_code', 'UNKNOWN')
        severity = item.get('severity', 'unknown')
        return SecurityFinding(
            check_id=(item.get('metadata') or {}).get('event_code', ''),
            check_title=(item.get('finding_info') or {}).get('title', ''),
            status=status,
            risk_level=self._determine_risk_level(status, severity),
            severity=severity,
            service=(resource.get('group') or {}).get('name', ''),
            region=resource.get('region', ''),
            resource_id=resource.get('uid', ''),
            resource_name=resource.get('name', ''),
            resource_type=resource.get('type', ''),
            description=item.get('message', ''),
            remediation=remediation.get('desc', '') if isinstance(remediation, dict) else str(remediation),
            compliance_frameworks=(item.get('unmapped') or {}).get('compliance', []),
            detected_at=datetime.now().isoformat()
        )

    def _determine_risk_level(self, status: str, severity: str) -> RiskLevel:
        """위험 등급 결정 (FAIL 은 Prowler 심각도를 그대로 사용, PASS·MANUAL 은 Info)"""
        if status == 'FAIL':
            severity_map = {
                'critical': RiskLevel.CRITICAL,
                'high': RiskLevel.HIGH,
                'medium': RiskLevel.MEDIUM,
                'low': RiskLevel.LOW
            }
            return severity_map.get(severity.lower(), RiskLevel.LOW)
        elif status == 'WARNING':
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.INFO
    
    def identify_assets(self) -> List[Asset]:
        """
        AWS 자산 자동 식별
        
        Returns:
            자산 리스트
        """
        logger.info("AWS 자산 식별 시작...")
        
        assets = []
        ec2_client = self.clients.get_client('ec2')
        s3_client = self.clients.get_client('s3')
        rds_client = self.clients.get_client('rds')
        lambda_client = self.clients.get_client('lambda')
        
        try:
            # EC2 인스턴스
            response = ec2_client.describe_instances()
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    asset = Asset(
                        asset_id=instance.get('InstanceId', ''),
                        asset_type='EC2',
                        asset_name=tags.get('Name', instance.get('InstanceId', '')),
                        service='ec2',
                        region=self.config.aws_region,
                        importance=self._assess_asset_importance(instance, tags),
                        confidentiality=self._assess_confidentiality(instance, tags),
                        integrity=self._assess_integrity(instance, tags),
                        availability=self._assess_availability(instance, tags),
                        owner=tags.get('Owner', ''),
                        tags=tags,
                        created_at=instance.get('LaunchTime', datetime.now()).isoformat() if instance.get('LaunchTime') else None
                    )
                    assets.append(asset)
            
            # S3 버킷
            response = s3_client.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                # S3 버킷 태그 조회 시도
                tags = {}
                try:
                    tag_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                except ClientError:
                    pass
                
                asset = Asset(
                    asset_id=bucket_name,
                    asset_type='S3',
                    asset_name=bucket_name,
                    service='s3',
                    region=self.config.aws_region,
                    importance=AssetImportance.HIGH,  # S3는 일반적으로 중요
                    confidentiality=4,  # 기본값
                    integrity=4,
                    availability=5,
                    owner=tags.get('Owner', ''),
                    tags=tags,
                    created_at=bucket.get('CreationDate', datetime.now()).isoformat() if bucket.get('CreationDate') else None
                )
                assets.append(asset)
            
            # RDS 인스턴스
            response = rds_client.describe_db_instances()
            for instance in response.get('DBInstances', []):
                tags = {tag['Key']: tag['Value'] for tag in instance.get('TagList', [])}
                asset = Asset(
                    asset_id=instance.get('DBInstanceIdentifier', ''),
                    asset_type='RDS',
                    asset_name=instance.get('DBInstanceIdentifier', ''),
                    service='rds',
                    region=self.config.aws_region,
                    importance=AssetImportance.CRITICAL,  # RDS는 일반적으로 매우 중요
                    confidentiality=5,
                    integrity=5,
                    availability=5,
                    owner=tags.get('Owner', ''),
                    tags=tags,
                    created_at=instance.get('InstanceCreateTime', datetime.now()).isoformat() if instance.get('InstanceCreateTime') else None
                )
                assets.append(asset)
            
            logger.info(f"총 {len(assets)}개의 자산 식별 완료")
            return assets
        
        except Exception as e:
            logger.error(f"자산 식별 실패: {e}")
            raise AssetCollectionError(f"자산 식별 실패: {e}")
    
    def _assess_asset_importance(self, resource: Dict, tags: Dict[str, str]) -> AssetImportance:
        """자산 중요도 평가 (CIA 기준)"""
        # 태그에서 중요도 정보 확인
        importance_tag = tags.get('Importance', tags.get('Criticality', ''))
        if importance_tag:
            importance_map = {
                'critical': AssetImportance.CRITICAL,
                'high': AssetImportance.HIGH,
                'medium': AssetImportance.MEDIUM,
                'low': AssetImportance.LOW
            }
            return importance_map.get(importance_tag.lower(), AssetImportance.MEDIUM)
        
        # 기본 평가 로직
        # 프로덕션 환경, 중요한 서비스 등은 높은 중요도
        env = tags.get('Environment', '').lower()
        if env in ['prod', 'production']:
            return AssetImportance.CRITICAL
        elif env in ['staging', 'test']:
            return AssetImportance.MEDIUM
        else:
            return AssetImportance.LOW
    
    def _assess_confidentiality(self, resource: Dict, tags: Dict[str, str]) -> int:
        """기밀성 평가 (1-5)"""
        # 데이터 분류 태그 확인
        data_class = tags.get('DataClassification', tags.get('Confidentiality', '')).lower()
        classification_map = {
            'public': 1,
            'internal': 2,
            'confidential': 4,
            'restricted': 5
        }
        return classification_map.get(data_class, 3)
    
    def _assess_integrity(self, resource: Dict, tags: Dict[str, str]) -> int:
        """무결성 평가 (1-5)"""
        # 중요도에 따라 평가
        importance = self._assess_asset_importance(resource, tags)
        importance_map = {
            AssetImportance.CRITICAL: 5,
            AssetImportance.HIGH: 4,
            AssetImportance.MEDIUM: 3,
            AssetImportance.LOW: 2
        }
        return importance_map.get(importance, 3)
    
    def _assess_availability(self, resource: Dict, tags: Dict[str, str]) -> int:
        """가용성 평가 (1-5)"""
        # 프로덕션 환경은 높은 가용성 요구
        env = tags.get('Environment', '').lower()
        if env in ['prod', 'production']:
            return 5
        elif env in ['staging']:
            return 4
        else:
            return 3
    
    def assets_from_findings(
        self,
        findings: List[SecurityFinding],
        known_assets: Sequence[Asset] = ()
    ) -> List[Asset]:
        """
        Prowler 발견 사항의 리소스(OCSF resources[].uid)로 자산 도출

        identify_assets() 인벤토리는 EC2·S3·RDS 만 다루고 ID 가 ARN 이 아니므로(예: 버킷 이름),
        인벤토리와 ID·이름이 일치하지 않는 리소스만 새 자산으로 추가합니다.
        """
        known = {asset.asset_id for asset in known_assets}
        derived: Dict[str, Asset] = {}
        for finding in findings:
            resource_id = finding.resource_id
            name_known = bool(finding.resource_name) and finding.resource_name in known
            if not resource_id or resource_id in known or resource_id in derived or name_known:
                continue
            derived[resource_id] = Asset(
                asset_id=resource_id,
                asset_type=finding.resource_type or finding.service,
                asset_name=finding.resource_name or resource_id,
                service=finding.service,
                region=finding.region,
                importance=AssetImportance.MEDIUM,  # 태그 정보가 없으므로 중간 중요도
                confidentiality=3,
                integrity=3,
                availability=3
            )
        return list(derived.values())

    def assess_risks(
        self,
        assets: List[Asset],
        findings: List[SecurityFinding]
    ) -> List[RiskAssessment]:
        """
        위험 평가 수행
        
        Args:
            assets: 자산 리스트
            findings: 보안 발견 사항 리스트
        
        Returns:
            위험 평가 리스트
        """
        logger.info("위험 평가 시작...")
        
        assessments = []
        
        # 자산별로 발견 사항 그룹화 (리소스 ARN 또는 이름이 자산 ID 와 일치)
        asset_findings: Dict[str, List[SecurityFinding]] = {asset.asset_id: [] for asset in assets}
        for finding in findings:
            for key in (finding.resource_id, finding.resource_name):
                if key and key in asset_findings:
                    asset_findings[key].append(finding)
                    break
        
        # 각 자산에 대한 위험 평가
        for asset in assets:
            asset_findings_list = asset_findings.get(asset.asset_id, [])
            
            # 위험 점수 계산
            risk_score = self._calculate_risk_score(asset, asset_findings_list)
            
            # 위험 등급 결정: 점수 등급과 가장 심각한 FAIL 발견 사항 등급 중 높은 쪽
            risk_level = max(
                [self._determine_risk_level_from_score(risk_score), *(f.risk_level for f in asset_findings_list)],
                key=RISK_LEVEL_ORDER.index
            )
            
            # 발견 사항 통계
            critical_count = sum(1 for f in asset_findings_list if f.risk_level == RiskLevel.CRITICAL)
            high_count = sum(1 for f in asset_findings_list if f.risk_level == RiskLevel.HIGH)
            medium_count = sum(1 for f in asset_findings_list if f.risk_level == RiskLevel.MEDIUM)
            low_count = sum(1 for f in asset_findings_list if f.risk_level == RiskLevel.LOW)
            
            assessment = RiskAssessment(
                asset_id=asset.asset_id,
                asset_name=asset.asset_name,
                risk_score=risk_score,
                risk_level=risk_level,
                findings=asset_findings_list,
                total_findings=len(asset_findings_list),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                assessed_at=datetime.now().isoformat()
            )
            
            assessments.append(assessment)
        
        logger.info(f"총 {len(assessments)}개의 자산에 대한 위험 평가 완료")
        return assessments
    
    def _calculate_risk_score(self, asset: Asset, findings: List[SecurityFinding]) -> float:
        """위험 점수 계산 (0-100)"""
        if not findings:
            return 0.0
        
        # 자산 중요도 가중치
        importance_weights = {
            AssetImportance.CRITICAL: 1.5,
            AssetImportance.HIGH: 1.2,
            AssetImportance.MEDIUM: 1.0,
            AssetImportance.LOW: 0.8
        }
        weight = importance_weights.get(asset.importance, 1.0)
        
        # 발견 사항별 점수
        base_scores = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 8,
            RiskLevel.LOW: 3,
            RiskLevel.INFO: 0  # PASS·MANUAL 은 위험 점수를 올리지 않음
        }
        
        total_score = sum(base_scores.get(f.risk_level, 0) for f in findings)
        weighted_score = min(total_score * weight, 100.0)
        
        return round(weighted_score, 2)
    
    def _determine_risk_level_from_score(self, score: float) -> RiskLevel:
        """위험 점수로부터 위험 등급 결정"""
        if score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def generate_risk_report(
        self,
        assessments: List[RiskAssessment],
        assets: List[Asset],
        findings: List[SecurityFinding]
    ) -> Path:
        """
        위험 관리 보고서 생성
        
        Args:
            assessments: 위험 평가 리스트
            assets: 자산 리스트
            findings: 보안 발견 사항 리스트
        
        Returns:
            보고서 파일 경로
        """
        logger.info("위험 관리 보고서 생성 중...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"isms_risk_report_{timestamp}.json"
        
        # 보고서 데이터 구성
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'ISMS-P 2025 Risk Assessment',
                'aws_region': self.config.aws_region,
                'total_assets': len(assets),
                'total_findings': len(findings),
                'total_assessments': len(assessments)
            },
            'summary': {
                'critical_risks': len([a for a in assessments if a.risk_level == RiskLevel.CRITICAL]),
                'high_risks': len([a for a in assessments if a.risk_level == RiskLevel.HIGH]),
                'medium_risks': len([a for a in assessments if a.risk_level == RiskLevel.MEDIUM]),
                'low_risks': len([a for a in assessments if a.risk_level == RiskLevel.LOW]),
                'average_risk_score': round(
                    sum(a.risk_score for a in assessments) / len(assessments) if assessments else 0, 2),
                'fail_findings_by_severity': {
                    level.value: sum(1 for f in findings if f.status == 'FAIL' and f.risk_level == level)
                    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW)
                },
                'findings_by_status': dict(Counter(f.status for f in findings))
            },
            'assets': [asdict(asset) for asset in assets],
            'assessments': [
                {
                    'asset_id': a.asset_id,
                    'asset_name': a.asset_name,
                    'risk_score': a.risk_score,
                    'risk_level': a.risk_level.value,
                    'total_findings': a.total_findings,
                    'critical_count': a.critical_count,
                    'high_count': a.high_count,
                    'medium_count': a.medium_count,
                    'low_count': a.low_count,
                    'assessed_at': a.assessed_at,
                    'findings': [
                        {
                            'check_id': f.check_id,
                            'check_title': f.check_title,
                            'status': f.status,
                            'risk_level': f.risk_level.value,
                            'severity': f.severity,
                            'service': f.service,
                            'description': f.description,
                            'remediation': f.remediation
                        }
                        for f in a.findings
                    ]
                }
                for a in assessments
            ],
            'findings': [
                {
                    'check_id': f.check_id,
                    'check_title': f.check_title,
                    'status': f.status,
                    'risk_level': f.risk_level.value,
                    'severity': f.severity,
                    'service': f.service,
                    'region': f.region,
                    'resource_id': f.resource_id,
                    'description': f.description,
                    'remediation': f.remediation,
                    'compliance_frameworks': f.compliance_frameworks
                }
                for f in findings
            ]
        }
        
        # JSON 파일로 저장
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"위험 관리 보고서 생성 완료: {report_file}")
        return report_file
    
    def run_full_assessment(self, compliance_framework: Optional[str] = ISMS_P_COMPLIANCE) -> Dict[str, Any]:
        """
        전체 평가 실행 (자산 식별 + 보안 점검 + 위험 평가)

        Args:
            compliance_framework: Prowler 컴플라이언스 이름 (기본: ISMS-P)
        
        Returns:
            평가 결과 딕셔너리
        """
        logger.info("=== ISMS-P 2025 전체 평가 시작 ===")
        
        try:
            # 1. 자산 식별
            logger.info("1단계: 자산 식별")
            assets = self.identify_assets()
            
            # 2. Prowler 보안 점검
            logger.info("2단계: Prowler 보안 점검")
            prowler_output = self.run_prowler_scan(output_format='json', compliance_framework=compliance_framework)
            
            # 3. 결과 파싱 (인벤토리에 없는 리소스는 발견 사항에서 자산으로 도출)
            logger.info("3단계: 결과 파싱")
            findings = self.parse_prowler_results(prowler_output)
            assets = assets + self.assets_from_findings(findings, assets)
            
            # 4. 위험 평가
            logger.info("4단계: 위험 평가")
            assessments = self.assess_risks(assets, findings)
            
            # 5. 보고서 생성
            logger.info("5단계: 보고서 생성")
            report_file = self.generate_risk_report(assessments, assets, findings)
            
            logger.info("=== ISMS-P 2025 전체 평가 완료 ===")
            
            return {
                'assets': assets,
                'findings': findings,
                'assessments': assessments,
                'report_file': report_file,
                'summary': {
                    'total_assets': len(assets),
                    'total_findings': len(findings),
                    'critical_risks': len([a for a in assessments if a.risk_level == RiskLevel.CRITICAL]),
                    'high_risks': len([a for a in assessments if a.risk_level == RiskLevel.HIGH])
                }
            }
        
        except Exception as e:
            logger.error(f"전체 평가 실패: {e}", exc_info=True)
            raise


def build_parser(config: Config) -> argparse.ArgumentParser:
    """명령행 인자 파서"""
    parser = argparse.ArgumentParser(
        description='ISMS-P 2025 Prowler 자산 식별 및 위험 평가 (Prowler 5.x)')
    parser.add_argument('--profile', default=config.aws_profile, help='AWS 프로필 (기본: twodragon)')
    parser.add_argument('--region', default=config.aws_region, help='AWS 리전 (기본: ap-northeast-2)')
    parser.add_argument('--compliance', default=ISMS_P_COMPLIANCE,
                        help=f'Prowler 컴플라이언스 이름 (기본: {ISMS_P_COMPLIANCE})')
    parser.add_argument('--output-dir', default=os.getenv('ISMS_OUTPUT_DIR', str(DEFAULT_OUTPUT_DIR)),
                        help='Prowler 결과·compliance/·위험 보고서 저장 디렉토리 '
                             '(기본: ISMS_OUTPUT_DIR 또는 스크립트 옆 output/)')
    parser.add_argument('--dry-run', action='store_true',
                        help='실행할 Prowler 명령만 출력하고 종료 (AWS 호출·스캔 없음)')
    return parser


def main(argv: Optional[List[str]] = None):
    """메인 함수"""
    config = Config.from_env()
    args = build_parser(config).parse_args(argv)
    config.aws_profile = args.profile
    config.aws_region = args.region
    config.output_dir = args.output_dir

    try:
        assessor = ProwlerISMS2025(config)
        if args.dry_run:
            cmd, _ = assessor.build_prowler_command(output_format='json', compliance_framework=args.compliance)
            print(shlex.join(cmd))
            return

        # 평가 실행
        results = assessor.run_full_assessment(compliance_framework=args.compliance)
        
        # 결과 출력
        print("\n=== 평가 결과 요약 ===")
        print(f"총 자산 수: {results['summary']['total_assets']}")
        print(f"총 발견 사항: {results['summary']['total_findings']}")
        print(f"Critical 위험: {results['summary']['critical_risks']}")
        print(f"High 위험: {results['summary']['high_risks']}")
        print(f"\n보고서 파일: {results['report_file']}")
    
    except Exception as e:
        logger.error(f"오류 발생: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

