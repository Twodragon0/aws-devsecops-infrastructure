terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "aws-sso-tfstate"
    key          = "ec2/terraform.tfstate"
    region       = "ap-northeast-2"
    encrypt      = true
    use_lockfile = true
  }
}
