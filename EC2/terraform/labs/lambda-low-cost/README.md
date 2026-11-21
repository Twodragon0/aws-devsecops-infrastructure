# 저비용 Lambda 보안 Finding 요약 실습

이 디렉터리는 상위 EC2 Terraform 구성과 **분리된 루트 모듈 및 로컬 상태 파일**을 사용합니다. Python 3.12 / Linux x86_64 Lambda가 전달받은 **합성 예제 Finding**의 심각도만 집계합니다. AWS 자산을 스캔하거나 Security Hub에 Finding을 전송하지 않습니다.

Terraform이 `handler.py`를 `lambda.zip`으로 묶습니다. 외부 Python 패키지나 레이어는 필요하지 않습니다. 생성 자원은 Lambda 함수, 함수 전용 IAM 역할 및 로그 권한, CloudWatch 로그 그룹뿐입니다. VPC, NAT Gateway, VPC 엔드포인트, EventBridge 일정, 자동 호출 트리거는 없습니다. 로그 보존은 1일이고 역할은 해당 로그 그룹의 스트림 생성 및 이벤트 기록만 허용합니다.

## 준비 및 로컬 확인

```bash
cd EC2/terraform/labs/lambda-low-cost
python3.12 -c 'import json, handler; print(json.dumps(handler.lambda_handler(json.load(open("sample-event.json")), None), indent=2))'
terraform init
terraform fmt -check
terraform validate
```

`terraform init`은 이 디렉터리에만 `.terraform/`, `.terraform.lock.hcl` 및 이후 로컬 상태 파일을 만듭니다. 별도 백엔드를 설정하지 않았으므로 상위 EC2 상태를 읽거나 변경하지 않습니다. AWS 자격 증명을 사용하기 전에도 핸들러 테스트, `fmt`, `validate`를 실행할 수 있습니다.

## 비용 및 변경 범위 확인

```bash
aws sso login --profile twodragon
AWS_PROFILE=twodragon terraform plan -out=lab.tfplan
terraform show lab.tfplan
```

`plan`에서 Lambda 함수 1개, IAM 역할/정책, 로그 그룹만 생성되는지 확인합니다. `plan`은 AWS 리소스를 만들지 않습니다. IAM 역할 이름이나 함수 이름이 기존 자원과 겹친다면 `-var='function_name=다른-고유-이름'`을 사용합니다.

## 수동 실습 및 정리

다음 명령은 **실제 AWS 자원을 생성하고 사용**하므로 계획을 확인한 후 실습 시에만 실행합니다.

```bash
AWS_PROFILE=twodragon terraform apply lab.tfplan
AWS_PROFILE=twodragon aws lambda invoke \
  --region ap-northeast-2 \
  --function-name "$(terraform output -raw function_name)" \
  --cli-binary-format raw-in-base64-out \
  --payload file://sample-event.json response.json
cat response.json
AWS_PROFILE=twodragon terraform destroy
```

`aws_region`을 바꿨다면 수동 호출 명령의 `--region`도 같은 값으로 바꿉니다.
호출 결과 예시는 `total: 3`, `high_priority: 2`입니다. 함수는 수동으로 호출할 때만 실행되며 리소스가 남아 있으면 Lambda 호출 및 CloudWatch Logs 사용량에 따라 요금이 생길 수 있습니다. 로그 보존 1일은 보관 기간만 제한하며, 전체 비용을 0원으로 보장하지 않습니다. 실습을 마치면 같은 디렉터리에서 `terraform destroy`가 완료됐는지 확인합니다. 상태 파일은 정리 확인 전까지 보관합니다.
