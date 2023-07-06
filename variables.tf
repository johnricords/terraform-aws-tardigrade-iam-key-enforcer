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
  description = "Name of the IAM role that the lambda will assume in the target account"
  type        = string
  default     = "E_IAM_KEY_ENFORCER"
}

variable "email_admin_report_enabled" {
  description = "Used to enable or disable the SES emailed report"
  type        = bool
  default     = false
}

variable "email_admin_report_subject" {
  description = "Subject of the report email that is sent"
  type        = string
  default     = null
}

variable "email_source" {
  description = "Email that will be used to send messages"
  type        = string
}

variable "email_banner_message" {
  description = "Messages that will be at the top of all emails sent to notify recipients of important information"
  type        = string
  default     = ""
}

variable "email_banner_message_color" {
  description = "Color of email banner message, must be valid html color"
  type        = string
  default     = "red"
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

variable "accounts" {
  description = "List of account objects to create events for"
  type = list(object({
    account_name       = string
    account_number     = string
    role_name          = optional(string) # deprecated
    armed              = bool
    debug              = optional(bool, false)
    email_user_enabled = bool
    email_targets      = list(string)
    exempt_groups      = list(string)
  }))
  default = []
}

variable "lambda" {
  description = "Map of any additional arguments for the upstream lambda module. See <https://github.com/terraform-aws-modules/terraform-aws-lambda>"
  type = object({
    artifacts_dir            = optional(string, "builds")
    build_in_docker          = optional(bool, false)
    create_package           = optional(bool, true)
    ephemeral_storage_size   = optional(number)
    ignore_source_code_hash  = optional(bool, true)
    local_existing_package   = optional(string)
    recreate_missing_package = optional(bool, false)
    runtime                  = optional(string, "python3.9")
    s3_bucket                = optional(string)
    s3_existing_package      = optional(map(string))
    s3_prefix                = optional(string)
    store_on_s3              = optional(bool, false)
    timeout                  = optional(number, 300)
    source_path = optional(object({
      patterns = optional(list(string), ["!\\.terragrunt-source-manifest"])
    }), {})
  })
  default = {}
}

variable "schedule_expression" {
  description = "Schedule Expressions for Rules"
  type        = string
  default     = "cron(0 1 ? * SUN *)"
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
