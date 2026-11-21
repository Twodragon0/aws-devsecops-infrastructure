output "function_name" {
  description = "Name to use for a manual test invocation."
  value       = aws_lambda_function.lab.function_name
}

output "log_group_name" {
  description = "CloudWatch Logs group with one-day retention."
  value       = aws_cloudwatch_log_group.lambda.name
}
