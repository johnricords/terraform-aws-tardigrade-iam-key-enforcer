variable "project_name" {
  description = "Project name to prefix resources with"
  type        = string
}

variable "compatible_python_runtimes" {
  description = "Compatible version of python to use defaults to 3.8"
  type        = list(string)
  default     = ["python3.8"]
}

variable "policy_assume_role_arn" {
  description = "The wildcard role arn that the lambda will be given permissions to assume"
  type        = string
}

variable "accounts" {
  description = "List of accounts to create scheduled events for"
  type = list(object({
    account_name       = string
    account_number     = string
    role_arn           = string
    armed              = bool
    email_user_enabled = bool
    email_target       = list(string)
    exempt_groups      = list(string)
  }))
}

variable "email_enabled" {
  description = "Used to enable or disable the SES emailed report"
  type        = bool
}

variable "email_subject" {
  description = "Subject of the report email that is sent"
  type        = string
}

variable "email_source" {
  description = "Email that will be used to send messages"
  type        = string
}

variable "email_tag" {
  description = "Tag to be placed on the IAM user that we can use to notify when their key is going to be disabled/deleted"
  type        = string
  default     = "keyenforcer:email"
}

variable "admin_email" {
  description = "Admin Email that will receive all emails and reports about actions taken if email is enabled"
  type        = string
}

variable "schedule_expression" {
  description = "Schedule Expressions for Rules"
  type        = string
}

variable "key_age_warning" {
  description = "Age at which to warn (e.g. 75)"
  type        = number
}

variable "key_age_inactive" {
  description = "Age at which a key should be inactive (e.g. 90)"
  type        = number
}

variable "key_age_delete" {
  description = "Age at which a key should be deleted (e.g. 120)"
  type        = number
}

variable "key_use_threshold" {
  description = "Age at which unused keys should be deleted (e.g.30)"
  type        = number
}

variable "s3_enabled" {
  description = "Set to 'true' and provide s3_bucket if the audit report should be written to S3"
  type        = bool
}

variable "s3_bucket" {
  description = "Bucket name to write the audit report to if s3_enabled is set to 'true'"
  type        = string
}

variable "s3_bucket_arn" {
  description = "Bucket arn to write the audit report to if s3_enabled is set to 'true'"
  type        = string
}

variable "sqs_queue_name" {
  description = "Resource name for the SQS Queue"
  type        = string
}

variable "message_retention_seconds" {
  description = "Max message retention in seconds (default is 14 days)"
  type        = number
  default     = 1209600
}

variable "visibility_timeout_seconds" {
  description = "The visibility timeout for the queue. An integer from 0 to 43200 (12 hours). The default for this attribute is 30."
  type        = number
  default     = 30
}

variable "log_level" {
  description = "Log level for lambda"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], var.log_level)
    error_message = "Valid values for log level are (CRITICAL, ERROR, WARNING, INFO, DEBUG)."
  }
}

variable "tags" {
  description = "Tags for resource"
  type        = map(string)
}
