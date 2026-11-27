# ISMS-P 2025 Prowler 활용 사용 예제

## 기본 사용법

### 1. AWS SSO 로그인

**중요:** 모든 스크립트 실행 전에 AWS SSO 로그인이 필요합니다.

```bash
# AWS SSO 로그인 (프로필: twodragon)
aws sso login --profile twodragon

# 로그인 상태 확인
aws sts get-caller-identity --profile twodragon
```

### 2. 전체 평가 실행

```bash
# 환경 변수 설정 (선택적, 기본값 사용 가능)
export AWS_PROFILE=twodragon  # 기본값
export AWS_REGION=ap-northeast-2  # 기본값
export ISMS_OUTPUT_DIR=./output

# 전체 평가 실행 (자산 식별 + 보안 점검 + 위험 평가), 결과는 output/ 에 저장
python prowler_isms_2025.py

# 옵션 확인, 스캔 없이 Prowler 명령만 출력
python prowler_isms_2025.py --help
python prowler_isms_2025.py --dry-run --profile twodragon --region ap-northeast-2

# 다른 컴플라이언스·출력 디렉토리로 실행
python prowler_isms_2025.py --compliance iso27001_2022_aws --output-dir ./output/iso27001
```

`--output-dir` 기본값은 `ISMS_OUTPUT_DIR`, 없으면 `isms-p-cloud-audit/output/` (`.gitignore` 대상) 입니다.

**출력:**
- `isms_risk_report_YYYYMMDD_HHMMSS.json`: 위험 평가 보고서
- `prowler_scan_YYYYMMDD_HHMMSS.ocsf.json`, `.csv`: Prowler 5.x 스캔 결과
- `compliance/prowler_scan_YYYYMMDD_HHMMSS_kisa_isms_p_2023_korean_aws.csv`: ISMS-P 항목별 결과

### 2. 대시보드 생성

```bash
# 위험 평가 보고서로부터 대시보드 생성
python risk_dashboard.py output/isms_risk_report_20241201_120000.json

# 출력 파일 지정
python risk_dashboard.py output/isms_risk_report_20241201_120000.json -o dashboard.html
```

## 고급 사용법

### 1. 특정 서비스만 점검

```python
from prowler_isms_2025 import ProwlerISMS2025
from utils.config import Config

# AWS SSO 로그인 필요: aws sso login --profile twodragon

config = Config.from_env()
# config.aws_profile = 'twodragon'  # 기본값
# config.aws_region = 'ap-northeast-2'  # 기본값

assessor = ProwlerISMS2025(config)

# EC2와 S3만 점검 (Prowler 5.x 에서 서비스 필터는 컴플라이언스 지정과 함께 쓸 수 없음)
prowler_output = assessor.run_prowler_scan(
    output_format='json',
    services=['ec2', 's3']
)
```

### 2. 컴플라이언스 프레임워크 지정 (ISMS-P, ISO 27001)

`run_prowler_scan(compliance_framework=...)`은 Prowler 5.x `--compliance` 옵션으로 전달되며, `run_full_assessment()`의 기본값은 `kisa_isms_p_2023_korean_aws`입니다.

```python
prowler_output = assessor.run_prowler_scan(
    output_format='json',                       # json-ocsf + csv 저장
    compliance_framework='iso27001_2022_aws'    # 또는 kisa_isms_p_2023_aws
)
```

CLI로 직접 실행할 수도 있습니다 (Prowler 5.52.0 기준).

```bash
# AWS SSO 로그인 필요: aws sso login --profile twodragon

# 프레임워크 이름 확인
prowler aws --list-compliance | grep -E "kisa|iso27001"

# ISMS-P (한국어 항목명)
prowler aws --profile twodragon --compliance kisa_isms_p_2023_korean_aws -o ./output

# ISMS-P + ISO/IEC 27001:2022
prowler aws --profile twodragon --compliance kisa_isms_p_2023_aws iso27001_2022_aws -o ./output
```

결과는 `./output/compliance/` 아래 프레임워크별 CSV로 저장됩니다.

### 3. 자산 중요도 수동 설정

AWS 태그를 통해 자산 중요도를 설정할 수 있습니다:

```bash
# EC2 인스턴스에 중요도 태그 추가
aws ec2 create-tags \
  --resources i-1234567890abcdef0 \
  --tags Key=Importance,Value=Critical \
         Key=DataClassification,Value=Restricted \
         Key=Environment,Value=Production
```

태그 옵션:
- `Importance`: Critical, High, Medium, Low
- `DataClassification`: Public, Internal, Confidential, Restricted
- `Environment`: Production, Staging, Test, Development

### 4. 위험 평가 결과 분석

```python
import json
from pathlib import Path

# 보고서 로드
with open('isms_risk_report_20241201_120000.json', 'r') as f:
    report = json.load(f)

# Critical 위험 자산 목록
critical_assets = [
    a for a in report['assessments']
    if a['risk_level'] == 'Critical'
]

print(f"Critical 위험 자산: {len(critical_assets)}개")
for asset in critical_assets:
    print(f"  - {asset['asset_name']}: {asset['risk_score']}점")
```

## 5주차: 멀티 계정 거버넌스 증적 수집

### 1. 실행

```bash
aws sso login --profile twodragon

# 관리 계정의 Control Tower 홈 리전에서 실행
python governance_audit.py --profile twodragon --region ap-northeast-2 --output-dir ./output
```

콘솔 요약 예시 (형식만 표시, 실제 값은 환경에 따라 다름):

```
[PASS   ] GOV-ORG-03 2.9.4/2.10.1   CloudTrail 변조 차단 SCP (StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors)
[FAIL   ] GOV-CT-05  2.9.4/2.11.3   S3 데이터 이벤트(GetObject 등 읽기) 수집
[UNKNOWN] GOV-CT-06  2.9.5/2.11.3   CloudWatch Logs 연동 (SIEM 수집 경로)
```

### 2. FAIL / UNKNOWN 항목만 추리기

```python
import json
from pathlib import Path

report_file = sorted(Path('output').glob('governance_evidence_*.json'))[-1]
report = json.loads(report_file.read_text(encoding='utf-8'))

for finding in report['findings']:
    if finding['status'] != 'PASS':
        print(finding['check_id'], finding['status'], finding['isms_p'], finding['detail'])

# 권한 부족으로 건너뛴 API
for error in report['errors']:
    print('skipped:', error['api'], error['code'])
```

### 3. 변조 차단 SCP 예외 주체 확인

`GOV-ORG-03`의 `evidence.exceptions`에는 Deny 문에서 제외된 주체(`ArnNotLike aws:PrincipalArn` 등)가 들어 있습니다. Control Tower 실행 역할(`AWSControlTowerExecution`)이나 브레이크글래스 역할 외의 예외가 있으면 심사 전에 사유를 문서화하세요.

```python
tamper = next(f for f in report['findings'] if f['check_id'] == 'GOV-ORG-03')
for exc in tamper['evidence'].get('exceptions', []):
    print(exc['policy'], exc['operator'], exc['key'], exc['values'])
```

### 4. 계정 ID를 가린 증적 공유

```bash
python governance_audit.py --mask-account-ids --output-dir ./share
```

12자리 계정 ID가 `********1234` 형태로 바뀝니다. 원본 출력은 `ISMS/.gitignore`에 의해 커밋되지 않지만, 공개 저장소나 수강생 채널에 올릴 때는 마스킹본을 쓰세요.

## CI/CD 통합

### GitHub Actions 예제

```yaml
name: ISMS-P Risk Assessment

on:
  schedule:
    - cron: '0 9 * * 1'  # 매주 월요일 오전 9시
  workflow_dispatch:

jobs:
  risk-assessment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r ISMS/requirements.txt
          pip install prowler
      
      - name: Configure AWS credentials (SSO)
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          role-session-name: GitHubActions
          aws-region: ap-northeast-2
      
      # 또는 AWS SSO 프로필 사용
      - name: Setup AWS SSO
        run: |
          aws configure set sso_start_url ${{ secrets.AWS_SSO_START_URL }}
          aws configure set sso_region ap-northeast-2
          aws configure set sso_account_id ${{ secrets.AWS_ACCOUNT_ID }}
          aws configure set sso_role_name ${{ secrets.AWS_ROLE_NAME }}
          aws sso login --profile twodragon
      
      - name: Run risk assessment
        run: |
          cd ISMS/isms-p-cloud-audit
          python prowler_isms_2025.py
      
      - name: Generate dashboard
        run: |
          cd ISMS/isms-p-cloud-audit
          python risk_dashboard.py output/isms_risk_report_*.json
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: risk-reports
          path: ISMS/isms-p-cloud-audit/output/
```

## Lambda 함수로 실행

### Lambda 함수 코드 예제

```python
import json
import os
from prowler_isms_2025 import ProwlerISMS2025
from utils.config import Config

def lambda_handler(event, context):
    """Lambda 함수 핸들러"""
    try:
        # 설정
        config = Config.from_env()
        config.output_dir = '/tmp/output'
        
        # 평가 실행
        assessor = ProwlerISMS2025(config)
        results = assessor.run_full_assessment()
        
        # 결과를 S3에 업로드 (선택적)
        # s3_client = boto3.client('s3')
        # s3_client.upload_file(
        #     str(results['report_file']),
        #     'isms-reports-bucket',
        #     f"reports/{results['report_file'].name}"
        # )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Risk assessment completed',
                'summary': results['summary']
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
```

### EventBridge 스케줄 설정

```json
{
  "Rules": [
    {
      "Name": "isms-weekly-risk-assessment",
      "ScheduleExpression": "cron(0 9 ? * MON *)",
      "State": "ENABLED",
      "Targets": [
        {
          "Arn": "arn:aws:lambda:ap-northeast-2:123456789012:function:isms-risk-assessment",
          "Id": "1"
        }
      ]
    }
  ]
}
```

## 알림 설정

### Slack 알림 예제

```python
import requests
import json
from pathlib import Path

def send_slack_notification(report_file: Path, webhook_url: str):
    """Slack으로 위험 평가 결과 알림 전송"""
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report['summary']
    
    message = {
        "text": "ISMS-P 2025 위험 평가 완료",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "ISMS-P 2025 위험 평가 결과"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical 위험:* {summary['critical_risks']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*High 위험:* {summary['high_risks']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*평균 위험 점수:* {summary['average_risk_score']}"
                    }
                ]
            }
        ]
    }
    
    response = requests.post(webhook_url, json=message)
    return response.status_code == 200
```

## 모니터링 및 추적

### 위험 추이 분석

```python
import json
from pathlib import Path
from datetime import datetime, timedelta

def analyze_risk_trends(reports_dir: Path, days: int = 30):
    """지난 N일간의 위험 추이 분석"""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    reports = []
    for report_file in reports_dir.glob('isms_risk_report_*.json'):
        report_time = datetime.strptime(
            report_file.stem.split('_')[-2] + '_' + report_file.stem.split('_')[-1],
            '%Y%m%d_%H%M%S'
        )
        
        if start_date <= report_time <= end_date:
            with open(report_file, 'r') as f:
                report = json.load(f)
                reports.append({
                    'date': report_time,
                    'summary': report['summary']
                })
    
    # 날짜순 정렬
    reports.sort(key=lambda x: x['date'])
    
    # 추이 분석
    for report in reports:
        print(f"{report['date'].strftime('%Y-%m-%d')}: "
              f"Critical={report['summary']['critical_risks']}, "
              f"Average Score={report['summary']['average_risk_score']}")
```

## 문제 해결

### Prowler 실행 시간이 오래 걸리는 경우

```python
# 특정 서비스만 점검하여 시간 단축
prowler_output = assessor.run_prowler_scan(
    output_format='json',
    services=['ec2', 's3', 'iam']  # 필요한 서비스만 지정
)
```

### 메모리 부족 오류

```python
# 배치 처리로 분할 실행
services_batches = [
    ['ec2', 's3'],
    ['rds', 'lambda'],
    ['iam', 'cloudfront']
]

for batch in services_batches:
    prowler_output = assessor.run_prowler_scan(
        output_format='json',
        services=batch
    )
```

## 참고 자료

- [Prowler 공식 문서](https://docs.prowler.com)
- [ISMS-P 인증 제도 안내 (KISA)](https://www.kisa.or.kr/1050602)
- [Prowler 컴플라이언스 문서](https://docs.prowler.com/user-guide/compliance/tutorials/compliance)
- [AWS Well-Architected 보안 원칙](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)

