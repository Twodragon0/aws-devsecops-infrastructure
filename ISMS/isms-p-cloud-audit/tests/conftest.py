"""
governance_audit 테스트 공통 설정

- 로컬 AWS 프로필/SSO 설정을 읽지 않도록 환경을 격리합니다.
- 테스트는 botocore Stubber만 사용하며 실제 AWS를 호출하지 않습니다.
"""

import os
import sys
from pathlib import Path

for _var in ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE'):
    os.environ.pop(_var, None)
os.environ['AWS_CONFIG_FILE'] = os.devnull
os.environ['AWS_SHARED_CREDENTIALS_FILE'] = os.devnull

# isms-p-cloud-audit/ (governance_audit) 와 ISMS/ (utils) 를 import 경로에 추가
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE.parent.parent))
