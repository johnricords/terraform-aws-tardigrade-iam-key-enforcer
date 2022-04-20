variable "project" {
  description = "Project name to prefix resources with"
  type        = string
  default     = "test-iam-key-enforcer"
}

variable "account_name" {
  description = "Account name referenced in report"
  type        = string
  default     = "TEST_ACCOUNT_NAME"
}

variable "email_target" {
  description = "Email to send reports to for an account"
  type        = string
}

variable "email_source" {
  description = "Email to send reports from"
  type        = string
  default     = "communications@dicelab.net"
}

variable "admin_email" {
  description = "Admin Email that report will be emailed to"
  type        = string
}

variable "key_age_warning" {
  description = "Age at which to warn (e.g. 75)"
  type        = number
  default     = 1
}

variable "key_age_inactive" {
  description = "Age at which a key should be inactive (e.g. 90)"
  type        = number
  default     = 2
}

variable "key_age_delete" {
  description = "Age at which a key should be deleted (e.g. 120)"
  type        = number
  default     = 2
}

variable "key_use_threshold" {
  description = "Age at which unused keys should be deleted (e.g.30)"
  type        = number
  default     = 1
}

variable "s3_enabled" {
  description = "Set to 'true' and provide s3_bucket if the audit report should be written to S3"
  type        = bool
  default     = true
}

variable "exempt_groups" {
  description = "Groups that are exempt from processing"
  type        = list(string)
  default = [
    "sample-group",
    "test-group",
    "other-group"
  ]
}

variable "contact_email" {
  description = "Contact Email"
  type        = string
  default     = "test"
}
