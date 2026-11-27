# 변경 이력

## [Prowler 오프라인 재평가·보고서 enum 직렬화] - 2026-11-27

### 추가
- `prowler_isms_2025.py --input <결과.json>`: 저장된 Prowler 결과(json-ocsf, 레거시 JSON)를 Prowler 실행·AWS 호출 없이 재평가. `--with-inventory` 를 줄 때만 `--profile` 로 인벤토리 조회, `--dry-run` 은 읽을 파일·출력 디렉토리만 출력, `--compliance` 와는 동시 사용 불가
- `risk_dashboard.py`: 자산 중요도 분포 표시 (`High` 와 이전 형식 `AssetImportance.HIGH` 모두 인식)

### 수정
- 보고서 JSON 에 자산 중요도가 `"AssetImportance.HIGH"` 로 저장되던 문제: Enum 을 값(`"High"`)으로 직렬화
- AWS 클라이언트를 처음 사용할 때 생성하도록 변경 (오프라인 모드에서 세션을 만들지 않음)

## [9기 5주차 거버넌스 증적] - 2026-11-27

### 추가
- `isms-p-cloud-audit/governance_audit.py`: 멀티 계정 거버넌스 증적 수집기 (읽기 전용)
  - Organizations 기능 세트, OU 트리, 대상별 SCP·RCP 연결
  - CloudTrail 변조 차단 Deny(StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors)와 `ArnNotLike` 등 예외 주체 추출
  - 조직 추적, 다중 리전, 로깅 상태, 무결성 검증, KMS, 기본/고급 이벤트 선택기의 S3 데이터 이벤트(읽기) 범위
  - 별도 계정 로그 버킷(중앙 로그 아카이브), CloudWatch Logs 연동, Control Tower 랜딩 존·드리프트
  - ISMS-P 인증기준 항목(2.1.3, 2.5.5, 2.6.1, 2.9.4, 2.9.5, 2.10.1, 2.11.3) 매핑 PASS/FAIL/UNKNOWN 증적을 JSON + CSV로 출력, `--mask-account-ids` 지원
  - 단독 계정(`AWSOrganizationsNotInUseException`), 멤버 계정, AccessDenied 를 중단 없이 UNKNOWN/FAIL로 기록
- `isms-p-cloud-audit/tests/`: botocore Stubber 기반 단위 테스트, `pytest.ini`

### 변경
- `README.md`: ISMS-P 인증기준 현황(2023.10.5 고시 개정, 101개 항목, 2026.4.10 강화방안) 추가, Prowler 5.x 컴플라이언스 이름(`kisa_isms_p_2023_aws`, `kisa_isms_p_2023_korean_aws`, `iso27001_2022_aws`)과 CLI 예시, 5주차 거버넌스 증적 수집 절차·최소 권한 IAM 정책·ISMS-P 매핑표, 9기 4주차 포스트 링크
- `isms-p-cloud-audit/README.md`, `USAGE_EXAMPLES.md`: `governance_audit.py` 사용법, Prowler 5.x 컴플라이언스 실행 방법, Python 요구 버전(3.10 이상 3.14 미만)
- 접속되지 않는 링크(`isms.go.kr`, AWS 보안 모범 사례 404)를 KISA ISMS-P 안내, 국가법령정보센터 고시, AWS Well-Architected 보안 원칙으로 교체

### 수정 (리뷰 반영)
- `governance_audit.py` 거짓 PASS 방지
  - 조건(`aws:RequestedRegion` 등)·Resource 제한·NotResource 가 있는 Deny 는 부분 적용(partial)으로만 기록
  - 주체 예외는 좁은 `aws:PrincipalArn` 패턴만 허용 (다른 `aws:Principal*` 키, `ForAllValues:`/`ForAnyValue:`, `*`·`arn:aws:iam::*:role/*` 같은 넓은 예외는 partial), SUSPENDED·폐쇄 계정은 판정 분모에서 제외
  - 변조 차단 범위를 Root → OU → 계정 상속으로 계정별 계산, 관리 계정 제외 모든 멤버 계정이 4개 액션을 상속해야 PASS, 미적용 OU·계정 목록 기록
  - `GetTrailStatus` 실패 시 CT-02~05, LOG-01 을 UNKNOWN 처리, 고급 이벤트 선택기 연산자(readOnly NotEquals, eventName StartsWith/NotStartsWith, ARN EndsWith 등) 처리
  - LOG-01 은 관리 계정에서만 판별 (ListBuckets 페이지네이션, GetBucketLocation + ExpectedBucketOwner), Control Tower 미발견 시 trusted access 로 FAIL/UNKNOWN 구분
  - `--mask-account-ids` 가 이메일, 역할 세션 이름, 계정·OU 이름까지 마스킹
  - IAM 와일드카드 매처, adaptive 재시도, boto3/botocore 1.35.60 이상, `requirements-dev.txt`
- `prowler_isms_2025.py`: Prowler 5.x CLI(`-M csv json-ocsf`, `-o`, `-F`, `--compliance kisa_isms_p_2023_korean_aws`, `--ignore-exit-code-3`)로 호출하고 json-ocsf 결과 파싱, `prowler>=5.0.0`
- `aws_info.py`: 들여쓰기가 깨져 실행되지 않던 문제 복구 (공백만 변경)
- 테스트 16개 → 70개

### 수정 (Prowler 5.52 실 스캔 결과 반영)
- `prowler_isms_2025.py` 위험 보고서가 FAIL 140건(Critical 2, High 22, Medium 76, Low 40)에도 위험 0건으로 나오던 문제
  - 원인: 자산 ID 는 boto3 인벤토리 값(버킷 이름 등)인데 OCSF `resources[].uid` 는 ARN 이라 424건 중 0건이 자산에 매칭됨, 인벤토리에 없는 IAM·CloudTrail 등 리소스는 평가 대상에서 빠짐
  - 발견 사항 리소스(ARN)로 자산을 도출하고 인벤토리 자산은 ARN, 리소스 이름, ARN 마지막 부분으로 매칭 (이름 매칭은 서비스·유형이 같을 때만), 다중 리소스 발견 사항은 자산별 한 번씩, 리소스가 없는 발견 사항은 `unassigned_findings` 로 집계
  - FAIL 위험 등급을 Prowler 심각도와 1:1 로 맞춤 (기존: High→Critical 등 한 단계 상향), PASS·MANUAL·WARNING 은 점수 0, 보고서 `findings[]` 에 `resource_name`, `resource_type` 추가
  - 자산 등급은 점수 등급과 가장 심각한 FAIL 등급 중 높은 쪽, `summary` 에 `fail_findings_by_severity`, `findings_by_status` 추가
- `python prowler_isms_2025.py --help` 가 도움말 대신 전체 스캔을 시작하던 문제: argparse 추가 (`--profile`, `--region`, `--compliance`, `--output-dir`, `--dry-run`)
- Prowler 결과와 `compliance/` 가 현재 작업 디렉토리에 생기던 문제: 기본 출력 위치를 `isms-p-cloud-audit/output/` 으로 변경, `--dry-run` 은 출력 디렉토리를 만들지 않음, `.gitignore` 에 `prowler_scan_*`, `isms_risk_report_*`, `compliance/` 추가
- 테스트 70개 → 87개

## [개선 버전] - 2024-12

### 주요 개선 사항

#### 1. 코드 구조 개선
- **모듈화**: 공통 기능을 `utils/` 모듈로 분리
  - `aws_clients.py`: AWS 클라이언트 중앙 관리
  - `config.py`: 환경 변수 기반 설정 관리
  - `logger.py`: 통합 로깅 시스템
  - `exporters.py`: 데이터 내보내기 유틸리티
  - `exceptions.py`: 커스텀 예외 클래스

#### 2. 코드 품질 향상
- **타입 힌팅**: 모든 함수에 타입 힌팅 추가
- **에러 처리**: 포괄적인 예외 처리 및 로깅
- **PEP 8 준수**: Python 코딩 스타일 가이드 준수
- **Docstring**: 모든 함수에 문서화 추가

#### 3. 보안 강화
- **하드코딩 제거**: 모든 설정을 환경 변수로 관리
- **자격 증명 관리**: AWS 자격 증명 하드코딩 완전 제거
- **로깅 개선**: 민감한 정보가 로그에 기록되지 않도록 개선
- **파일 권한**: `.gitignore`에 출력 파일 추가

#### 4. 기능 개선
- **통합 로깅**: 모든 스크립트에 일관된 로깅 시스템 적용
- **에러 복구**: 부분 실패 시에도 가능한 데이터 수집 계속
- **출력 형식**: 타임스탬프가 포함된 파일명으로 중복 방지
- **설정 유연성**: 환경 변수를 통한 설정 관리

#### 5. 문서화
- **README 개선**: 상세한 사용법 및 보안 가이드 추가
- **의존성 관리**: `requirements.txt` 추가
- **예제 코드**: 각 스크립트에 사용 예제 포함

### 변경된 파일

#### 새로 생성된 파일
- `utils/__init__.py`
- `utils/aws_clients.py`
- `utils/config.py`
- `utils/logger.py`
- `utils/exporters.py`
- `utils/exceptions.py`
- `requirements.txt`
- `.gitignore`
- `CHANGELOG.md`

#### 개선된 파일
- `aws_info.py`: 완전히 재작성, 클래스 기반 구조로 변경
- `ec2_info.py`: 모듈화 및 에러 처리 개선
- `s3_info.py`: 보안 점검 기능 강화
- `s3_script.py`: 상세 보안 정보 수집 개선
- `Lambda_info.py`: 타입 힌팅 및 에러 처리 추가
- `route53_info.py`: 모듈화 및 에러 처리 개선
- `ec2_eni.py`: 코드 구조 개선
- `eks_info.py`: Kubernetes 클라이언트 에러 처리 개선
- `ec2_s3_drive.py`: Google Drive 업로드 안정성 개선
- `README.md`: 사용법 및 보안 가이드 추가

### 마이그레이션 가이드

#### 기존 스크립트 사용자

1. **의존성 설치**
   ```bash
   pip install -r requirements.txt
   ```

2. **환경 변수 설정** (선택적)
   ```bash
   export AWS_REGION=ap-northeast-2
   export ISMS_OUTPUT_DIR=./output
   ```

3. **스크립트 실행 방법 동일**
   ```bash
   python aws_info.py
   ```

#### 주요 변경 사항

- **하드코딩된 경로 제거**: `ec2_s3_drive.py`의 서비스 계정 파일 경로는 환경 변수로 관리
- **출력 파일명 변경**: 타임스탬프가 포함된 파일명으로 자동 생성
- **로깅 추가**: 모든 스크립트에 로깅 기능 추가

### 향후 계획

- [ ] 단위 테스트 추가
- [ ] CI/CD 파이프라인 통합
- [ ] 추가 AWS 서비스 지원 (ElastiCache, Redshift 등)
- [ ] 데이터베이스 백엔드 지원 (PostgreSQL, MySQL)
- [ ] 대시보드 통합

