variable "project_name" {
  description = "Project name to prefix resources with"
  type        = string
}

variable "compatible_python_runtimes" {
  description = "Compatible version of python to use defaults to 3.8"
  type        = list(string)
  default     = ["python3.8"]
}

variable "assume_role_name" {
  description = "The wildcard role arn that the lambda will be given permissions to assume"
  type        = string
}

variable "email_admin_report_enabled" {
  description = "Used to enable or disable the SES emailed report"
  type        = bool
  default     = false
}

variable "email_subject" {
  description = "Subject of the report email that is sent"
  type        = string
  default     = null
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
  default     = false
}

variable "s3_bucket" {
  description = "Bucket name to write the audit report to if s3_enabled is set to 'true'"
  type        = string
  default     = null
}

variable "s3_bucket_arn" {
  description = "Bucket arn to write the audit report to if s3_enabled is set to 'true'"
  type        = string
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
  default     = {}
}
