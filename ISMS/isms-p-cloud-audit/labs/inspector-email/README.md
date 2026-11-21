# Amazon Inspector 취약점 이메일 알림

Amazon Inspector가 서울 리전의 기본 EventBridge 버스로 보낸 활성 HIGH 및
CRITICAL Finding을 선택합니다. Python 3.12 Lambda는 심각도, 취약점 ID, 유형,
리전, Inspector 콘솔 링크를 SNS 이메일로 보냅니다. 전체 Finding과 AWS 자원
식별자는 메일 본문에 넣지 않습니다. 로그 보존은 1일입니다.

## 배포 및 확인

1. `twodragon` SSO 세션과 대상 리전의 Inspector 상태를 확인합니다.
2. `template.yaml`을 CloudFormation으로 검증한 후, 수신자 주소를
   `RecipientEmail`에 전달해 스택을 생성합니다. 생성에는 `CAPABILITY_IAM`이
   필요합니다. 주소를 소스나 커밋에 저장하지 않습니다.
3. 수신자가 SNS 구독 확인 메일의 **Confirm subscription**을 누릅니다. 구독이
   대기 중이면 SNS는 취약점 알림을 전달하지 않습니다.
4. 이미 쓰는 스캔 유형이 없다면 비용과 리전의 스캔 범위를 확인한 뒤 필요한
   유형만 별도로 활성화합니다. 이 템플릿은 Inspector나 Security Hub를 활성화하지
   않습니다. Lambda 표준 스캔은 해당 리전의 적격 함수에 적용될 수 있습니다.
5. 실제 Finding 이벤트가 도착하면 Lambda 호출, SNS 발행 및 수신 메일을 확인합니다.
   기존 Finding의 일괄 재전송은 지원하지 않습니다. AWS 이벤트의 재시도로 같은
   알림이 다시 도착할 수 있습니다.

```bash
aws inspector2 batch-get-account-status --profile twodragon --region ap-northeast-2
aws cloudformation validate-template --profile twodragon --region ap-northeast-2 \\
  --template-body file://ISMS/isms-p-cloud-audit/labs/inspector-email/template.yaml
```

비용이나 수신 경로를 확인하기 전에는
[합성 이벤트 패턴 실습](../securityhub-prowler/)으로 EventBridge 필터를 검증할 수
있습니다. 합성 검증은 실제 스캔이나 이메일 수신 증거가 아닙니다. 실습을 종료할
때는 이 알림 스택을 삭제하고, 이번 실습 때문에 새로 활성화한 스캔 유형만
별도로 비활성화합니다.

- [Inspector 이벤트 스키마](https://docs.aws.amazon.com/inspector/latest/user/eventbridge-integration.html)
- [SNS 이메일 구독](https://docs.aws.amazon.com/sns/latest/dg/sns-email-notifications.html)
- [Inspector 사용량과 비용](https://docs.aws.amazon.com/inspector/latest/user/usage.html)
