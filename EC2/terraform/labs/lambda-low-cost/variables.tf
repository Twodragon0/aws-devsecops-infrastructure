variable "aws_region" {
  description = "Region for this isolated training lab."
  type        = string
  default     = "ap-northeast-2"
}

variable "function_name" {
  description = "Name of the manually invoked training Lambda."
  type        = string
  default     = "aws-devsecops-low-cost-lab"
}
