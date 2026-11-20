# 4주차 실습: Prowler 결과를 Security Hub CSPM에서 보기

이 실습은 [온라인 교육 저장소](https://github.com/Twodragon0/online-course)의 4주차 자산 목록 → ISMS-P 점검 → 개선 과제 흐름을 확장합니다. 기존 `ISMS/isms-p-cloud-audit`의 Prowler 스캔 결과를 로컬 CSV/ASFF로 확인한 뒤, **선택한 실습 계정·리전**에서만 Security Hub CSPM으로 FAIL Finding을 보냅니다. 새 Security Hub의 OCSF 노출 분석과는 다른 연동입니다.

## 구조와 비용 경계

| 단계 | 계정 변경 | 결과 |
| :--- | :--- | :--- |
| 템플릿 검증·로컬 Prowler 실행 | 없음 | CSV, ASFF JSON |
| `EnableLab=true`로 스택 생성 | CSPM 활성화, Prowler 제품 구독 | Finding 수신 준비 |
| `--security-hub` 실행 | FAIL Finding을 CSPM에 전송 | 콘솔에서 조사·집계 |

`template.yaml`의 `EnableLab` 기본값은 `false`이며 기본 표준과 새 통제 자동 활성화도 꺼 둡니다. **스택 생성 또는 Finding 전송은 CSPM 사용 요금이 발생할 수 있습니다.** Prowler 스캔 자체는 기존 AWS 설정을 바꾸지 않지만 API 호출량과 기존 서비스 사용량을 확인하세요. 이 실습은 Config, GuardDuty, CloudTrail, EventBridge, SNS를 새로 켜지 않습니다. `ISMS/examples/automated-audit.tf`는 더 넓은 자원을 만들므로 이 실습에 사용하지 않습니다.

한 번 `EnableLab=true`로 만든 스택을 나중에 `false`로 **업데이트하면 CloudFormation이 Hub와 구독을 삭제**합니다. `false`는 새 템플릿의 준비용 기본값일 뿐, 실행 중인 스택의 안전한 일시정지 스위치가 아닙니다. 스택을 업데이트하거나 삭제할 때는 Change Set으로 삭제 영향을 확인하고, 다른 점검이 Hub를 사용 중인지 먼저 확인합니다.

## 1. 범위와 현재 상태 확인

아래 명령은 저장소 루트에서 실행합니다. 계정 ID·자원 ID와 원본 Finding은 교육 저장소에 커밋하지 않습니다.

```bash
aws sso login --profile twodragon
aws sts get-caller-identity --profile twodragon
aws securityhub describe-hub --profile twodragon --region ap-northeast-2
```

마지막 명령에서 `InvalidAccessException`이 나오면 해당 리전의 CSPM이 아직 꺼진 상태입니다. 2026-11-20에 `twodragon`의 서울 리전은 꺼져 있었습니다. 이미 켜져 있거나 다른 스택·조직 정책이 소유한다면 **이 템플릿으로 Hub를 다시 만들지 않습니다.** 실습 계정과 리전, 예산 한도, 실습 종료 후 처리 방식을 먼저 정합니다.

## 2. 변경 없는 Prowler 스캔

`prowler` 5.50.0에서 확인한 명령입니다. 로컬 `output/`은 `.gitignore`로 제외됩니다. CSV는 4주차 과제 변환기에, ASFF는 Security Hub 형식 확인에 사용합니다. 기존 CSV만으로는 Security Hub `BatchImportFindings`에 바로 넣을 수 없습니다.

```bash
cd ISMS/isms-p-cloud-audit/labs/securityhub-prowler
umask 077
prowler aws --profile twodragon --region ap-northeast-2 \
  --compliance kisa_isms_p_2023_korean_aws \
  --output-formats csv json-asff --output-directory ./output
```

같은 실행에서 나온 기본 Finding CSV와 `output/compliance/`의 ISMS-P CSV를 짝지어 4주차 로컬 패키지의 `tistory-blog/week4-cloud-security/scripts/prowler_ismsp_to_tasks.py`에 전달합니다. 이 패키지는 아직 교육 저장소의 기본 브랜치에 게시되지 않았으므로 해당 스크립트가 없는 환경에서는 CSV의 인증기준별 `STATUS`를 직접 집계합니다. `MANUAL`은 수동 증적 계획으로, `FAIL`은 검사 단위 개선 과제 **후보**로 처리합니다. PASS를 인증기준 충족으로 해석하지 않습니다.

## 3. CloudFormation 준비와 선택적 생성

실습 계정에서 템플릿 구문을 먼저 검증합니다. 이 명령은 스택을 만들지 않습니다.

```bash
aws cloudformation validate-template --profile twodragon --region ap-northeast-2 \
  --template-body file://template.yaml
```

내일 해당 계정에서 CSPM 활성화와 비용을 확인한 **뒤에만** 다음 명령을 사용합니다. 이 스택은 서울 리전에 Hub를 새로 만들고 Prowler 제품을 구독합니다. 기존 Hub에는 적용하지 않습니다.

```bash
printf '승인된 실습 계정 ID (12자리): '
read -r EXPECTED_ACCOUNT
ACTUAL_ACCOUNT="$(aws sts get-caller-identity --profile twodragon --query Account --output text)"
if [[ "$EXPECTED_ACCOUNT" =~ ^[0-9]{12}$ && "$ACTUAL_ACCOUNT" = "$EXPECTED_ACCOUNT" ]]; then
  if aws cloudformation create-stack --profile twodragon --region ap-northeast-2 \
    --stack-name week4-securityhub-prowler-lab \
    --template-body file://template.yaml \
    --parameters ParameterKey=EnableLab,ParameterValue=true && \
    aws cloudformation wait stack-create-complete --profile twodragon \
      --region ap-northeast-2 --stack-name week4-securityhub-prowler-lab; then
    aws securityhub list-enabled-products-for-import --profile twodragon \
      --region ap-northeast-2
  else
    printf '스택 생성 또는 완료 대기가 실패했습니다. 스택 이벤트를 확인합니다.\n' >&2
    false
  fi
else
  printf '승인된 계정과 현재 SSO 계정이 달라 중단합니다.\n' >&2
  false
fi
```

`ProductSubscriptions`에 `product-subscription/prowler/prowler`가 있는지 확인합니다. CloudFormation이 실패하면 스택 이벤트를 읽고 원인을 해결합니다. 기존 Hub나 제품 구독을 덮어쓰지 않습니다.

## 4. FAIL Finding만 선택적으로 전송

Hub와 제품 구독을 확인한 후에 실행합니다. `--skip-sh-update`는 일부 검사만 실행했을 때 이전 Prowler Finding을 이번 결과에 없다는 이유로 보관 처리하는 것을 막습니다. `--send-sh-only-fails`는 전송만 FAIL로 제한하고 로컬 파일에는 전체 결과를 남깁니다.

```bash
printf '승인된 실습 계정 ID (12자리): '
read -r EXPECTED_ACCOUNT
ACTUAL_ACCOUNT="$(aws sts get-caller-identity --profile twodragon --query Account --output text)"
if [[ "$EXPECTED_ACCOUNT" =~ ^[0-9]{12}$ && "$ACTUAL_ACCOUNT" = "$EXPECTED_ACCOUNT" ]]; then
  if aws securityhub describe-hub --profile twodragon --region ap-northeast-2 >/dev/null && \
    SUBSCRIPTIONS="$(aws securityhub list-enabled-products-for-import --profile twodragon \
      --region ap-northeast-2 --query 'ProductSubscriptions[]' --output text)" && \
    [[ "$SUBSCRIPTIONS" == *'/prowler/prowler'* ]]; then
    prowler aws --profile twodragon --region ap-northeast-2 \
      --compliance kisa_isms_p_2023_korean_aws \
      --output-formats csv json-asff --output-directory ./output \
      --security-hub --send-sh-only-fails --skip-sh-update
  else
    printf 'Security Hub CSPM 또는 Prowler 제품 구독을 확인할 수 없어 전송하지 않습니다.\n' >&2
    false
  fi
else
  printf '승인된 계정과 현재 SSO 계정이 달라 전송하지 않습니다.\n' >&2
  false
fi
```

Security Hub CSPM 콘솔에서 제품을 Prowler로 필터링하고, 계정·리전·실행 시각과 전송 건수를 대조합니다. 전송에 실패한 Finding은 Prowler 로그에서 확인합니다. 서비스의 PASS/FAIL은 ISMS-P 인증 판정이 아닙니다.

## 제출 및 종료

1. 계정(마스킹)·리전·실행 시각·Prowler 버전, 로컬 CSV/ASFF 생성 여부
2. 인증기준별 PASS/FAIL/MANUAL 집계와 MANUAL 5개 증적 계획
3. 전송을 했다면 Prowler 제품 Finding 수와 개선 과제 카드 3건(담당자·기한·재점검 기준 포함)
4. 켠 서비스, 예상·실제 비용 확인 방법, 실습 종료 시각과 보존할 Finding 여부

스택 삭제는 Hub를 비활성화하고 Prowler 제품 구독도 해제하므로, 다른 점검이 이 Hub를 사용하지 않는지 확인한 뒤에만 실행합니다. 원본 `output/`에는 계정·자원 식별자가 있으므로 공유하거나 커밋하지 않습니다.

실습 종료 시 **이 스택이 처음 만든 Hub**이고 다른 워크로드가 사용하지 않는다고 확인한 경우에만 아래 정리 명령을 실행합니다. 삭제 후 Hub가 남아 있거나 `DELETE_FAILED`이면 CloudFormation 스택 이벤트와 별도 소유권을 확인합니다. 기존 Hub를 사용한 계정에는 이 명령을 적용하지 않습니다.

```bash
printf '승인된 실습 계정 ID (12자리): '
read -r EXPECTED_ACCOUNT
ACTUAL_ACCOUNT="$(aws sts get-caller-identity --profile twodragon --query Account --output text)"
printf '이 실습 스택의 Hub와 구독을 삭제하려면 DELETE 입력: '
read -r DELETE_CONFIRMATION
if [[ "$EXPECTED_ACCOUNT" =~ ^[0-9]{12}$ && "$ACTUAL_ACCOUNT" = "$EXPECTED_ACCOUNT" && "$DELETE_CONFIRMATION" = DELETE ]]; then
  if aws cloudformation delete-stack --profile twodragon --region ap-northeast-2 \
    --stack-name week4-securityhub-prowler-lab && \
    aws cloudformation wait stack-delete-complete --profile twodragon \
      --region ap-northeast-2 --stack-name week4-securityhub-prowler-lab; then
    if HUB_STATUS="$(aws securityhub describe-hub --profile twodragon --region ap-northeast-2 2>&1)"; then
      printf 'Hub가 여전히 활성화되어 있습니다. 소유권과 비용을 확인합니다.\n' >&2
      false
    elif [[ "$HUB_STATUS" == *InvalidAccessException* ]]; then
      printf 'Security Hub CSPM 비활성화를 확인했습니다.\n'
    else
      printf 'Hub 조회 실패 원인을 확인할 수 없어 비활성화를 검증하지 못했습니다.\n' >&2
      false
    fi
  else
    printf '삭제가 완료되지 않았습니다. CloudFormation 스택 이벤트를 확인합니다.\n' >&2
    false
  fi
else
  printf '계정이 다르거나 삭제 확인이 없어 정리하지 않았습니다.\n' >&2
  false
fi
```

## 근거

- [AWS CloudFormation Hub](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-securityhub-hub.html), [Prowler 제품 구독](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-securityhub-productsubscription.html)
- [Prowler Security Hub 연동](https://docs.prowler.com/user-guide/providers/aws/securityhub), [출력 형식](https://docs.prowler.com/user-guide/cli/tutorials/reporting)
- [AWS Security Hub CSPM 요금](https://aws.amazon.com/security-hub/cspm/pricing/)
