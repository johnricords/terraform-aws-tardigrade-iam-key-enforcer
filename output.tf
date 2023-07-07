output "lambda" {
  description = "The lambda module object"
  value       = module.lambda
}

output "queue" {
  description = "The SQS Queue resource object"
  value       = aws_sqs_queue.this
}
