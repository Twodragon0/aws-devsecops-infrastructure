# ISMS-P 구축 및 인증 가이드

## 개요

이 문서는 **정보보호 관리체계(ISMS)** 및 **개인정보보호 관리체계(PIMS)**를 통합한 **ISMS-P**를 구축하고 인증받기 위한 절차와 방법을 안내하는 자료입니다. **ISMS-P**는 정보보호와 개인정보보호를 통합적으로 관리할 수 있는 체계로, 기업의 정보보호 역량을 향상시키고 개인정보의 안전한 처리를 보장합니다.

## 프로젝트 목적

ISMS-P 인증을 통해 조직은 정보자산의 보안성을 강화하고, 개인정보의 안전한 처리를 보장함으로써 각종 법적, 규제적 요구사항을 준수하게 됩니다. 이 가이드는 ISMS-P 인증을 위한 체계 구축부터 운영 및 유지관리 방안을 다룹니다.

## 🏗️ ISMS-P 아키텍처

### ISMS-P 관리 체계 구조

```mermaid
graph TB
    subgraph "정보보호 관리체계"
        Policy[정보보호 정책]
        Procedure[절차 및 지침]
        Standard[표준 및 가이드라인]
    end
    
    subgraph "정보자산 관리"
        AssetInventory[자산 목록<br/>EC2, S3, RDS 등]
        AssetClassification[자산 분류<br/>중요도 평가]
        AssetOwnership[자산 소유권<br/>책임자 지정]
    end
    
    subgraph "취약점 관리"
        VulnerabilityScan[취약점 스캔<br/>정기 점검]
        PatchManagement[패치 관리<br/>보안 업데이트]
        RiskAssessment[위험 평가<br/>리스크 분석]
    end
    
    subgraph "접근 제어"
        IAM[IAM 정책<br/>최소 권한]
        MFA[MFA 인증<br/>다중 인증]
        NetworkACL[네트워크 ACL<br/>접근 제어]
    end
    
    subgraph "모니터링 및 감사"
        CloudTrail[CloudTrail<br/>API 로깅]
        Config[AWS Config<br/>규칙 준수]
        GuardDuty[GuardDuty<br/>위협 탐지]
        LogAnalysis[로그 분석<br/>이상 탐지]
    end
    
    subgraph "사고 대응"
        IncidentResponse[사고 대응 계획]
        Forensics[포렌식 분석]
        Recovery[복구 절차]
    end
    
    subgraph "컴플라이언스"
        LegalReview[법적 준수 검토]
        Audit[내부/외부 감사]
        Certification[ISMS-P 인증]
    end
    
    Policy --> AssetInventory
    Procedure --> VulnerabilityScan
    Standard --> IAM
    
    AssetInventory --> AssetClassification
    AssetClassification --> AssetOwnership
    
    VulnerabilityScan --> PatchManagement
    PatchManagement --> RiskAssessment
    
    IAM --> MFA
    MFA --> NetworkACL
    
    CloudTrail --> LogAnalysis
    Config --> LogAnalysis
    GuardDuty --> LogAnalysis
    LogAnalysis --> IncidentResponse
    
    IncidentResponse --> Forensics
    Forensics --> Recovery
    
    AssetInventory --> LegalReview
    RiskAssessment --> Audit
    Audit --> Certification
    
    style Policy fill:#e1f5ff
    style AssetInventory fill:#fff4e1
    style LogAnalysis fill:#e8f5e9
    style Certification fill:#f3e5f5
```

### ISMS-P 구축 프로세스

```mermaid
sequenceDiagram
    participant Org as 조직
    participant Team as ISMS 팀
    participant AWS as AWS 인프라
    participant Audit as 감사원
    participant Cert as 인증기관
    
    Org->>Team: ISMS-P 구축 시작
    Team->>Team: 자산 식별 및 목록화
    Team->>AWS: AWS 리소스 조사
    AWS-->>Team: 자산 목록 반환
    
    Team->>Team: 취약점 스캔
    Team->>Team: 위험 평가
    Team->>Team: 보안 정책 수립
    
    Team->>AWS: 보안 통제 구현
    AWS-->>Team: 구현 완료
    
    Team->>Team: 내부 감사
    Team->>Audit: 외부 감사 요청
    Audit->>AWS: 인프라 검토
    Audit->>Team: 감사 결과 보고
    
    Team->>Team: 개선 조치
    Team->>Cert: 인증 신청
    Cert->>AWS: 인증 심사
    Cert-->>Org: ISMS-P 인증 발급
```

### 정보 흐름 및 보안 통제

```mermaid
graph LR
    subgraph "데이터 수집"
        User[사용자]
        App[애플리케이션]
        API[API Gateway]
    end
    
    subgraph "데이터 처리"
        Lambda[Lambda Function]
        ECS[ECS Container]
        EC2[EC2 Instance]
    end
    
    subgraph "데이터 저장"
        S3[S3 Bucket<br/>암호화]
        RDS[RDS Database<br/>암호화]
        DynamoDB[DynamoDB<br/>암호화]
    end
    
    subgraph "보안 통제"
        Encryption[암호화<br/>KMS]
        AccessControl[접근 제어<br/>IAM]
        Monitoring[모니터링<br/>CloudTrail]
        Backup[백업<br/>자동화]
    end
    
    User --> App
    App --> API
    API --> Lambda
    API --> ECS
    API --> EC2
    
    Lambda --> S3
    Lambda --> RDS
    ECS --> DynamoDB
    EC2 --> RDS
    
    S3 --> Encryption
    RDS --> Encryption
    DynamoDB --> Encryption
    
    Lambda --> AccessControl
    ECS --> AccessControl
    EC2 --> AccessControl
    
    Lambda --> Monitoring
    ECS --> Monitoring
    EC2 --> Monitoring
    
    S3 --> Backup
    RDS --> Backup
    DynamoDB --> Backup
    
    style Encryption fill:#e1f5ff
    style AccessControl fill:#fff4e1
    style Monitoring fill:#e8f5e9
    style Backup fill:#f3e5f5
```

## ISMS-P 인증 신청 유형

### 자율신청자

**자율신청자**는 법적으로 ISMS 인증 의무 대상자에 해당하지 않지만, 자발적으로 정보보호 및 개인정보보호 관리체계를 구축·운영하고자 하는 기업 및 기관을 의미합니다. 자율신청자는 ISMS-P 인증을 희망할 경우 자율적으로 인증심사를 신청할 수 있습니다.

### ISMS 인증 의무대상자

**ISMS 인증 의무대상자**는 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 제47조 2항에 따라 일정 기준을 충족하는 기업 및 기관입니다. 아래는 의무대상자 기준을 요약한 내용입니다:

- **ISP(인터넷 서비스 제공자)**: 「전기통신사업법」 제6조제1항에 따라 허가를 받은 자로서 서울특별시 및 모든 광역시에서 정보통신망서비스를 제공하는 자
- **IDC(인터넷 데이터 센터)**: 「정보통신망법」 제46조에 따른 집적정보통신시설 사업자
- **의무대상자 기준**: 다음 조건 중 하나라도 해당하는 자
  - 연간 매출액 또는 세입이 1,500억원 이상인 자
  - 상급종합병원(「의료법」 제3조의4)
  - 재학생 수가 1만 명 이상인 학교(「고등교육법」 제2조)
  - 정보통신서비스 부문 전년도 매출액이 100억원 이상인 자
  - 전년도 일일평균 정보통신서비스 이용자 수가 100만 명 이상인 자

## 프로젝트 범위

- **대상 조직**: 정보자산과 개인정보를 취급하는 모든 기업 및 기관
- **적용 영역**:
  - 서버, 네트워크, 데이터베이스, 클라우드 환경
  - 개인정보 처리 흐름 및 정보 보호 관리체계

## ISMS-P 구축 절차

### 1. 자산 식별 및 관리
   - **정보자산 식별**: 서버, 데이터베이스, 네트워크 장비, 클라우드 계정 등의 자산을 식별하고 관리합니다.
   - **자산 중요도 평가**: 기밀성, 무결성, 가용성(CIA)을 기준으로 각 자산의 중요도를 평가합니다.
   - **자산 목록 유지**: 자산 위치, 상태, 보안 조치 현황을 기록하고 주기적으로 업데이트합니다.

### 2. 취약점 관리
   - **취약점 스캐닝**: 서버, 네트워크 장비, 데이터베이스의 보안 취약점을 주기적으로 점검하고 개선합니다.
   - **클라우드 보안 감사**: AWS, Azure 등의 클라우드 계정에 대한 주기적인 보안 감사 및 모니터링을 수행합니다.

### 3. 법적 준거성 확보
   - **법적 요구사항 준수**: 정보통신망법, 개인정보 보호법 등 관련 법률을 준수합니다.
   - **법적 점검 결과 기록**: 법적 요구사항을 충족하는지 여부를 점검하고 이를 문서화합니다.

### 4. 정보 흐름 분석
   - **정보 흐름도 작성**: 조직 내에서 정보가 어떻게 처리되고 이동하는지 시각적으로 표현하여 보안 리스크를 식별합니다.
   - **개인정보 흐름도 작성**: 개인정보가 수집, 처리, 저장되는 경로를 파악하고 보호 조치를 적용합니다.

### 5. 위험 평가 및 대응
   - **위험 평가**: 잠재적인 보안 위협을 식별하고, 그 발생 가능성과 영향을 평가합니다.
   - **위험 완화 계획**: 고위험 영역에 대한 대응 계획을 수립하고, 위험을 최소화할 수 있는 방안을 마련합니다.

### 6. 보안 정책 및 절차 개발
   - **보안 정책 수립**: 정보보호 정책, 개인정보 처리 방침, 접근 제어 및 사고 대응 계획을 수립하고 주기적으로 검토합니다.
   - **지침 및 매뉴얼 개발**: 직원들이 이해할 수 있도록 사용 지침과 매뉴얼을 작성하고 배포합니다.

### 7. 보안 교육 및 인식 강화
   - **보안 교육 프로그램**: 정보보호와 개인정보보호에 관한 교육을 전 직원에게 정기적으로 실시합니다.
   - **지속적 교육**: 새로운 보안 위협과 규제 변화에 대해 지속적으로 교육합니다.

## 주요 산출물
- **위험 평가 보고서**: 식별된 취약점과 위험 요소, 그리고 이에 대한 대응 방안을 기록한 보고서.
- **자산 목록**: 모든 정보자산의 목록과 보호 조치 현황.
- **정보 흐름도**: 데이터 및 개인정보의 흐름을 시각화한 도면.
- **법적 준수 체크리스트**: 관련 법률과 규정을 충족했는지 점검한 내용.
- **사고 대응 계획**: 정보 유출이나 보안 사고 발생 시 대응 절차.

## 인증 절차

1. **초기 검토 및 감사**: 내부적으로 정책, 자산, 취약점을 검토합니다.
2. **갭 분석**: 현재 상태와 ISMS-P 요구사항 간의 격차를 분석합니다.
3. **통제 조치 구현**: 발견된 격차를 해결하기 위한 보안 통제 조치를 적용합니다.
4. **인증 심사**: 외부 심사원에 의해 ISMS-P 인증 심사를 받습니다.
5. **지속적인 모니터링**: 주기적으로 보안 체계를 점검하고 새로운 취약점에 대해 대응합니다.

## AWS 자산 수집 스크립트 사용법

이 디렉토리에는 ISMS-P 인증을 위한 AWS 자산 정보를 자동으로 수집하는 Python 스크립트들이 포함되어 있습니다.

### 사전 요구 사항

1. **Python 3.9 이상** (Prowler 5.x를 함께 쓰려면 Python 3.10 이상 3.14 미만)
2. **AWS 자격 증명 설정**
   - AWS CLI 설정 (`aws configure`)
   - 또는 환경 변수 (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
   - 또는 IAM 역할 (EC2/Lambda에서 실행 시)

3. **의존성 설치**
   ```bash
   pip install -r requirements.txt
   ```

### 환경 변수 설정

스크립트 실행 전 다음 환경 변수를 설정할 수 있습니다:

```bash
# AWS 설정 (기본값 사용 시 생략 가능)
export AWS_REGION=ap-northeast-2  # 기본값
export AWS_PROFILE=twodragon  # 기본값: twodragon

# 출력 설정
export ISMS_OUTPUT_DIR=./output
export ISMS_OUTPUT_FORMAT=csv  # csv, xlsx, json

# 로깅 설정
export ISMS_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
export ISMS_LOG_FILE=./logs/isms.log  # 선택적

# Google Drive 설정 (ec2_s3_drive.py용, 선택적)
export GOOGLE_SERVICE_ACCOUNT_FILE=/path/to/service-account.json
```

### 사용 가능한 스크립트

#### 1. `aws_info.py` - 전체 AWS 자산 정보 수집

모든 AWS 서비스의 자산 정보를 Excel 파일로 수집합니다.

```bash
python aws_info.py
```

**수집 항목:**
- EC2 인스턴스
- S3 버킷
- ECR 리포지토리
- IAM 역할 및 정책
- Route 53 호스티드 존 및 레코드
- RDS 인스턴스
- CloudFront 배포
- Lambda 함수

**출력:** `aws_assets_isms_p_YYYYMMDD_HHMMSS.xlsx`

#### 2. `ec2_info.py` - EC2 인스턴스 정보 수집

```bash
python ec2_info.py
```

**출력:** `ec2_info_YYYYMMDD_HHMMSS.csv`

#### 3. `s3_info.py` - S3 버킷 정보 수집

```bash
python s3_info.py
```

**출력:** `s3_buckets_info_YYYYMMDD_HHMMSS.csv`

#### 4. `s3_script.py` - S3 버킷 보안 설정 점검

S3 버킷의 보안 설정을 상세히 점검합니다.

```bash
python s3_script.py
```

**점검 항목:**
- 버킷 암호화
- 버킷 로깅
- ACL 설정
- 버킷 정책
- 퍼블릭 액세스 차단
- 암호화 규칙

**출력:** `s3_bucket_info_YYYYMMDD_HHMMSS.csv`

#### 5. `Lambda_info.py` - Lambda 함수 정보 수집

```bash
python Lambda_info.py
```

**출력:** `aws_lambda_inventory_YYYYMMDD_HHMMSS.csv`

#### 6. `route53_info.py` - Route 53 레코드 정보 수집

```bash
python route53_info.py
```

**출력:** `route53_records_YYYYMMDD_HHMMSS.csv`

#### 7. `ec2_eni.py` - EC2 네트워크 인터페이스 정보 수집

```bash
python ec2_eni.py
```

**출력:** `instance_details_YYYYMMDD_HHMMSS.csv`

#### 8. `eks_info.py` - EKS 클러스터 노드 정보 수집

**주의:** Kubernetes 클러스터 접근 권한이 필요합니다.

```bash
# Kubernetes 클라이언트 설치
pip install kubernetes

# kubeconfig 설정
export KUBECONFIG=~/.kube/config

python eks_info.py
```

**출력:** `eks_nodes_info_YYYYMMDD_HHMMSS.csv`

#### 9. `ec2_s3_drive.py` - Google Drive 업로드

EC2 및 S3 정보를 수집하여 Google Drive에 업로드합니다.

```bash
# Google Drive API 라이브러리 설치
pip install gspread oauth2client

# 서비스 계정 파일 설정
export GOOGLE_SERVICE_ACCOUNT_FILE=/path/to/service-account.json

python ec2_s3_drive.py
```

**출력:**
- 로컬: `aws_assets_isms_p_YYYYMMDD_HHMMSS.xlsx`
- Google Drive: 자동 생성된 스프레드시트

### 스크립트 구조

```
ISMS/
├── utils/              # 공통 유틸리티 모듈
│   ├── __init__.py
│   ├── aws_clients.py  # AWS 클라이언트 관리
│   ├── config.py       # 설정 관리
│   ├── logger.py       # 로깅 유틸리티
│   ├── exporters.py    # 데이터 내보내기
│   └── exceptions.py   # 커스텀 예외
├── aws_info.py         # 전체 자산 수집
├── ec2_info.py         # EC2 정보 수집
├── s3_info.py          # S3 정보 수집
├── s3_script.py        # S3 보안 점검
├── Lambda_info.py      # Lambda 정보 수집
├── route53_info.py     # Route 53 정보 수집
├── ec2_eni.py          # EC2 ENI 정보 수집
├── eks_info.py         # EKS 정보 수집
├── ec2_s3_drive.py     # Google Drive 업로드
├── isms-p-cloud-audit/ # Prowler 위험 평가, 거버넌스 증적, 실습(labs/)
│   ├── prowler_isms_2025.py   # 자산 식별 + Prowler 위험 평가
│   ├── risk_dashboard.py      # 위험 대시보드(HTML)
│   ├── governance_audit.py    # 5주차 멀티 계정 거버넌스 증적 (읽기 전용)
│   └── tests/                 # governance_audit 단위 테스트 (botocore Stubber)
├── pytest.ini          # 테스트 경로 설정 (cd ISMS && python -m pytest)
├── requirements.txt    # 의존성 목록
└── README.md           # 이 파일
```

## 보안 가이드

### 자격 증명 관리

1. **AWS SSO 사용 (권장)**
   - AWS SSO를 통한 중앙화된 인증 관리
   - 프로필 기반 인증 사용 (기본값: `twodragon`)
   ```bash
   # SSO 로그인
   aws sso login --profile twodragon
   
   # 세션 확인
   aws sts get-caller-identity --profile twodragon
   ```

2. **절대 하드코딩 금지**
   - AWS 자격 증명을 코드에 직접 작성하지 마세요
   - AWS SSO 프로필 또는 환경 변수 사용

3. **최소 권한 원칙**
   - 스크립트 실행에 필요한 최소한의 권한만 부여
   - SSO 역할에 필요한 권한:
     - `ec2:DescribeInstances`
     - `s3:ListBuckets`, `s3:GetBucket*`
     - `iam:ListRoles`, `iam:GetRolePolicy`, `iam:GetPolicy`
     - `route53:ListHostedZones`, `route53:ListResourceRecordSets`
     - `rds:DescribeDBInstances`
     - `cloudfront:ListDistributions`
     - `lambda:ListFunctions`
     - `ecr:DescribeRepositories`
     - `sts:GetCallerIdentity` (인증 확인용)

4. **SSO 세션 관리**
   - SSO 세션은 일반적으로 8-12시간 유효
   - 세션 만료 시 `aws sso login --profile twodragon` 재실행

### 출력 파일 보안

1. **민감 정보 포함 주의**
   - 수집된 데이터에는 IAM 정책, 버킷 정책 등 민감한 정보가 포함될 수 있습니다
   - 출력 파일을 안전하게 보관하고 접근을 제한하세요

2. **파일 권한 설정**
   ```bash
   chmod 600 output/*.csv
   chmod 600 output/*.xlsx
   ```

3. **저장 위치**
   - 출력 파일을 버전 관리 시스템에 커밋하지 마세요
   - `.gitignore`에 출력 디렉토리 추가:
     ```
     output/
     *.csv
     *.xlsx
     logs/
     ```

### 로깅 보안

1. **로그 파일 보안**
   - 로그 파일에 민감한 정보가 기록되지 않도록 주의
   - 로그 파일 접근 권한 제한

2. **CloudWatch Logs 통합** (선택적)
   - 프로덕션 환경에서는 CloudWatch Logs 사용 권장
   - 로그 암호화 및 보존 정책 설정

### 네트워크 보안

1. **VPC 엔드포인트 사용** (선택적)
   - 인터넷을 통하지 않고 AWS 서비스에 접근
   - VPC 내에서 실행 시 VPC 엔드포인트 구성 권장

2. **프록시 설정** (필요 시)
   - 기업 네트워크에서 실행 시 프록시 설정 가능
   ```bash
   export HTTP_PROXY=http://proxy.example.com:8080
   export HTTPS_PROXY=http://proxy.example.com:8080
   ```

## 문제 해결

### 일반적인 오류

1. **AWS 연결 실패**
   ```
   Error: AWS 연결 실패. 자격 증명을 확인하세요.
   ```
   - 해결: `aws configure` 실행 또는 환경 변수 확인

2. **권한 부족**
   ```
   ClientError: An error occurred (AccessDenied) when calling the DescribeInstances operation
   ```
   - 해결: IAM 정책에서 필요한 권한 추가

3. **모듈 없음**
   ```
   ImportError: No module named 'pandas'
   ```
   - 해결: `pip install -r requirements.txt` 실행

### 디버깅

로깅 레벨을 DEBUG로 설정하여 상세한 정보 확인:

```bash
export ISMS_LOG_LEVEL=DEBUG
python aws_info.py
```

## ISMS-P 인증기준 현황 (2026-11-27 확인)

이 저장소의 "ISMS-P 2025"는 강의 회차 이름이며, KISA가 2025년에 새 인증기준을 낸 것은 아닙니다. 현재 심사에 쓰이는 기준은 다음과 같습니다.

| 구분 | 내용 |
|------|------|
| 인증기준 | 「정보보호 및 개인정보보호 관리체계 인증 등에 관한 고시」 2023.10.5 개정 (개인정보보호위원회고시 제2023-8호) 별표 7 |
| 항목 수 | 101개 = 관리체계 수립 및 운영 16 + 보호대책 요구사항 64 + 개인정보 처리단계별 요구사항 21 |
| 안내서 | 세부점검항목 2023.10.31, 인증기준 안내서 2023.11.23 개정 |
| 이후 변경 | 2024.7.24 고시 개정으로 중소기업 간편인증(ISMS-P 특례) 시행. 2026.4.10 정부 "인증 실효성 강화방안" 발표: 101개 표준 기준에 강화 인증기준 20개를 더하는 안으로, 2027년 적용 목표 (확정 전) |

- 고시 원문: [국가법령정보센터](https://www.law.go.kr/행정규칙/정보보호및개인정보보호관리체계인증등에관한고시)
- 인증 제도 안내: [KISA ISMS-P](https://www.kisa.or.kr/1050602)
- 강화방안 보도: [뉴시스 2026-04-10](https://www.newsis.com/view/NISX20260409_0003584993)

### Prowler 컴플라이언스 프레임워크 (Prowler 5.52.0, 2026-11-23 PyPI 기준)

| 프레임워크 | Prowler 이름 |
|-----------|--------------|
| ISMS-P (영문) | `kisa_isms_p_2023_aws` |
| ISMS-P (한국어) | `kisa_isms_p_2023_korean_aws` |
| ISO/IEC 27001:2022 | `iso27001_2022_aws` (구판: `iso27001_2013_aws`) |

```bash
# 사용 가능한 프레임워크 목록
prowler aws --list-compliance

# ISMS-P 기준 점검 (결과: output/compliance/ 아래 CSV)
prowler aws --profile twodragon --compliance kisa_isms_p_2023_korean_aws

# ISO 27001:2022 와 함께 점검
prowler aws --profile twodragon --compliance kisa_isms_p_2023_aws iso27001_2022_aws
```

> `prowler_isms_2025.py`의 내부 Prowler 호출(`-M json`, `-f <파일>`, `-c <프레임워크>`)은 Prowler 3.x 옵션입니다. Prowler 5.x에서 `-f`는 리전 필터, `-c`는 체크 지정이므로, 컴플라이언스 점검은 위 CLI를 직접 실행하세요. 프레임워크 상세: [Prowler Hub](https://hub.prowler.com/compliance/kisa_isms_p_2023_aws), [Compliance 문서](https://docs.prowler.com/user-guide/compliance/tutorials/compliance)

## ISMS-P 2025 Prowler 활용 방안

### Prowler를 활용한 자산 식별 및 위험 관리

ISMS-P 2025 최신 가이드에 따라 Prowler를 활용한 자동화된 자산 식별 및 위험 관리 시스템을 제공합니다.

**주요 기능:**
- AWS 자산 자동 식별 및 중요도 평가 (CIA 기준)
- Prowler 보안 점검 통합
- 위험 등급 자동 부여 및 우선순위 관리
- 위험 관리 대시보드 생성

**사용법:**
```bash
# 1. AWS SSO 로그인 (필수)
aws sso login --profile twodragon

# 2. Prowler 설치
pip install prowler

# 3. 통합 자산 식별 및 위험 평가 실행
cd isms-p-cloud-audit
python prowler_isms_2025.py

# 4. 위험 관리 대시보드 생성
python risk_dashboard.py isms_risk_report_20241201_120000.json
```

**AWS SSO 설정:**
- 기본 프로필: `twodragon`
- 기본 리전: `ap-northeast-2`
- 자세한 설정 방법: [`isms-p-cloud-audit/AWS_SSO_SETUP.md`](isms-p-cloud-audit/AWS_SSO_SETUP.md) 참조

**자세한 내용:** [`isms-p-cloud-audit/README.md`](isms-p-cloud-audit/README.md) 참조

### 위험 평가 기준 (ISMS-P 2025)

- **Critical (80점 이상)**: 즉시 조치 필요
  - 보안 정책 위반
  - 암호화 미설정
  - 퍼블릭 액세스 허용

- **High (60-79점)**: 우선 조치 필요
  - 로깅 미설정
  - 버전 관리 미설정
  - 백업 미설정

- **Medium (40-59점)**: 계획적 조치 필요
  - 태그 미설정
  - 모니터링 알림 미설정

- **Low (20-39점)**: 모니터링 필요
  - 최적화 권장 사항

## 5주차 거버넌스 증적 수집 (Organizations, Control Tower, CloudTrail)

클라우드 시큐리티 9기 5주차(멀티 계정 거버넌스) 실습용 수집기입니다. `isms-p-cloud-audit/governance_audit.py`는 **읽기 전용 API만** 호출해 아래 항목을 확인하고, ISMS-P 인증기준 번호를 붙인 PASS / FAIL / UNKNOWN 증적을 JSON과 CSV로 남깁니다.

- **Organizations**: 기능 세트(ALL), OU 트리와 계정, 대상(Root/OU/계정)별 SCP·RCP 연결
- **CloudTrail 변조 차단 SCP**: `cloudtrail:StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` Deny를 Root → OU → 계정 경로로 상속받는지 계정별로 계산합니다. 관리 계정을 뺀 모든 멤버 계정이 4개 액션을 모두 상속받아야 PASS이며, 빠진 OU·계정을 증적에 남깁니다. 리전 조건(`aws:RequestedRegion` 등)이 붙거나 Resource가 특정 추적으로 좁혀진 Deny는 부분 적용(partial)으로만 기록합니다. `ArnNotLike aws:PrincipalArn` 같은 주체 예외는 허용하되 목록으로 남깁니다. SCP는 관리 계정에 적용되지 않습니다.
- **조직 추적**: 조직 추적 여부, 다중 리전, 로깅 상태(`GetTrailStatus`), 로그 파일 무결성 검증, SSE-KMS
- **S3 데이터 이벤트**: 기본/고급 이벤트 선택기에서 GetObject 등 읽기 이벤트를 어떤 버킷에 대해 수집하는지
- **중앙 로그 아카이브**: 관리 계정에서 실행할 때 추적 버킷이 관리 계정 소유가 아닌지 (`ListBuckets` 페이지네이션, 권한이 없으면 `GetBucketLocation` + `ExpectedBucketOwner`). 다른 계정에서 실행하면 UNKNOWN
- **SIEM 수집 경로**: CloudWatch Logs 연동 여부 (S3 기반 SIEM은 수동 확인 → UNKNOWN)
- **Control Tower**: 랜딩 존 상태·드리프트, 활성화된 컨트롤 수. 랜딩 존이 안 보이면 Organizations trusted access(`controltower.amazonaws.com`)로 "미사용(FAIL)"과 "다른 홈 리전(UNKNOWN)"을 구분

### 실행

```bash
aws sso login --profile twodragon
cd isms-p-cloud-audit

# 관리 계정(또는 Organizations 위임 관리자 계정), Control Tower 홈 리전에서 실행
python governance_audit.py --profile twodragon --region ap-northeast-2 --output-dir ./output

# 수강생과 공유할 때는 계정 ID·이메일·역할 세션 이름·계정/OU 이름 마스킹
python governance_audit.py --mask-account-ids --output-dir ./output
```

출력: `governance_evidence_YYYYMMDD_HHMMSS.json` (원본 응답 + 판정), `governance_evidence_YYYYMMDD_HHMMSS.csv` (항목별 판정, 수집 시각 포함). 두 파일 모두 `ISMS/.gitignore`(`*.json`, `*.csv`, `output/`)로 커밋에서 제외됩니다.

- 단독 계정(`AWSOrganizationsNotInUseException`)은 조직 항목을 FAIL로 기록하고 CloudTrail 점검은 계속합니다.
- 멤버 계정이나 권한이 부족한 경우 해당 항목만 UNKNOWN으로 남기고 `errors`에 API와 오류 코드를 기록합니다. `GetTrailStatus`가 실패해 로깅 여부를 확인하지 못하면 추적 관련 항목도 FAIL 대신 UNKNOWN입니다.
- 정책 본문을 읽지 못한 SCP(`DescribePolicy` 실패)가 미적용 계정의 경로에 있으면 GOV-ORG-03은 UNKNOWN이며, 분석하지 못한 정책 이름을 남깁니다.
- API 호출은 adaptive 재시도(최초 호출 포함 최대 10회)를 사용합니다.

### 필요한 IAM 권한 (최소 권한, 읽기 전용)

수집기가 호출하는 API와 정확히 같은 16개 액션입니다 (`sts:GetCallerIdentity`는 권한이 필요 없음). IAM 정책 린터 [parliament](https://github.com/duo-labs/parliament)로 액션 이름과 리소스 범위를 검증했습니다 (경고 0건). `DescribeOrganization`을 제외한 조직 구조·정책 조회(`ListRoots`, `ListPolicies` 등)는 관리 계정 또는 위임 관리자 계정에서만 결과를 돌려줍니다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrganizationsList",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListAccountsForParent",
        "organizations:ListPolicies",
        "organizations:ListAWSServiceAccessForOrganization"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsPolicyRead",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribePolicy",
        "organizations:ListTargetsForPolicy"
      ],
      "Resource": "arn:aws:organizations::*:policy/*"
    },
    {
      "Sid": "CloudTrailList",
      "Effect": "Allow",
      "Action": "cloudtrail:DescribeTrails",
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailTrailRead",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "arn:aws:cloudtrail:*:*:trail/*"
    },
    {
      "Sid": "ControlTowerList",
      "Effect": "Allow",
      "Action": [
        "controltower:ListLandingZones",
        "controltower:ListEnabledControls"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ControlTowerLandingZoneRead",
      "Effect": "Allow",
      "Action": "controltower:GetLandingZone",
      "Resource": "arn:aws:controltower:*:*:landingzone/*"
    },
    {
      "Sid": "LogArchiveOwnershipCheck",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    },
    {
      "Sid": "LogArchiveOwnerFallback",
      "Effect": "Allow",
      "Action": "s3:GetBucketLocation",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

### 점검 항목과 ISMS-P 매핑

항목 번호·명칭은 2023.10.5 고시 개정 인증기준을 따릅니다 (Prowler `kisa_isms_p_2023_korean_aws` 매핑 파일로 교차 확인). 매핑은 증적 정리용 참고 자료이며 심사 판정을 대신하지 않습니다.

| 점검 ID | 내용 | ISMS-P 인증기준 |
|---------|------|-----------------|
| GOV-ORG-01 | Organizations 모든 기능(ALL) 활성화 | 2.1.3 정보자산 관리, 2.5.5 특수 계정 및 권한 관리 |
| GOV-ORG-02 | 사용자 정의 SCP 연결 | 2.5.5 특수 계정 및 권한 관리 |
| GOV-ORG-03 | CloudTrail 변조 차단 SCP를 모든 멤버 계정이 상속 (조건·리소스 제한은 partial, 주체 예외 기록) | 2.9.4 로그 및 접속기록 관리, 2.10.1 보안시스템 운영 |
| GOV-ORG-04 | 사용자 정의 RCP 연결 | 2.5.5 특수 계정 및 권한 관리, 2.6.1 네트워크 접근 |
| GOV-CT-01 | 조직 추적 로깅 | 2.9.4 로그 및 접속기록 관리, 2.11.3 이상행위 분석 및 모니터링 |
| GOV-CT-02 | 다중 리전 추적 | 2.9.4 |
| GOV-CT-03 | 로그 파일 무결성 검증 | 2.9.4 |
| GOV-CT-04 | SSE-KMS 암호화 | 2.9.4, 2.10.1 |
| GOV-CT-05 | S3 데이터 이벤트(읽기) 수집 | 2.9.4, 2.11.3 |
| GOV-CT-06 | CloudWatch Logs 연동 (SIEM 수집 경로) | 2.9.5 로그 및 접속기록 점검, 2.11.3 |
| GOV-LOG-01 | 별도 계정 중앙 로그 아카이브 (관리 계정에서 실행 시 판별) | 2.9.4 |
| GOV-CTW-01 | Control Tower 랜딩 존 ACTIVE + 드리프트 없음 | 2.10.1 보안시스템 운영 |

참고 문서: [RCP](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html), [SCP](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [조직 추적](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html), [데이터 이벤트](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html), [Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html)

### 테스트

```bash
cd ISMS
pip install -r requirements-dev.txt
python -m pytest        # 실제 AWS 호출 없이 botocore Stubber로 실행
```

## 자동화

### Cron 작업 설정

정기적으로 자산 정보를 수집하려면 cron 작업을 설정하세요:

```bash
# 매일 오전 9시에 실행
0 9 * * * cd /path/to/ISMS && /usr/bin/python3 aws_info.py >> /var/log/isms.log 2>&1

# 매주 월요일 오전 9시에 위험 평가 실행
0 9 * * 1 cd /path/to/ISMS/isms-p-cloud-audit && /usr/bin/python3 prowler_isms_2025.py >> /var/log/isms_risk.log 2>&1
```

### Lambda 함수로 실행

스크립트를 Lambda 함수로 변환하여 정기적으로 실행할 수 있습니다. `examples/automated-audit.tf`를 참조하세요.

## 결론

**ISMS-P 인증**을 통해 조직은 정보자산의 보안성을 강화하고, 개인정보 보호를 위한 법적 요구사항을 충족할 수 있습니다. 이 문서의 가이드라인을 따름으로써 조직은 정보보호 관리체계를 구축하고 ISMS-P 인증을 효율적으로 준비할 수 있습니다.

이 스크립트들을 사용하여 AWS 자산 정보를 자동으로 수집하고, ISMS-P 인증 준비에 활용하세요.

## 라이선스
이 프로젝트는 MIT 라이선스 하에 제공됩니다.

---

## 📝 관련 블로그 포스트

이 프로젝트와 관련된 블로그 포스트를 참고하세요:

- 클라우드 시큐리티 9기 5주차 (게시 예정)
- [클라우드 시큐리티 9기 4주차: 자산 목록에서 ISMS-P 증적까지, 점검 결과를 개선 과제로 닫기](https://twodragon.tistory.com/715)
- [클라우드 시큐리티 8기 4주차: 통합 보안 취약점 점검 및 ISMS-P 인증 대응 실무](https://twodragon.tistory.com/705)
- [클라우드 시큐리티 8기 3주차: AWS FinOps 아키텍처부터 ISMS-P 보안 감사까지 완벽 공략!](https://twodragon.tistory.com/703)
- [클라우드 보안 과정 7기 - 4주차 AWS 취약점 점검 및 ISMS 대응 가이드](https://twodragon.tistory.com/682)

더 많은 블로그 포스트는 [Twodragon 블로그](https://twodragon.tistory.com)에서 확인하실 수 있습니다.
