variable "project_name" {
  description = "Project name to prefix resources with"
}

variable "account_number" {
  description = "Account number to inspect"
  type        = string
}

variable "account_name" {
  description = "Account name to inspect"
  type        = string
}

variable "key_age_warning" {
  description = "Number in days before key expiration that we begin warning"
  type        = number
  default     = 14
}

variable "key_age_inactive" {
  description = "The number in days before key expiration that we make the key inactive"
  type        = number
  default     = 0
}

variable "key_age_delete" {
  description = "Number in days before key expiration that we delete the key"
  type        = number
  default     = 14
}

variable "exempt_group" {
  description = "List of users who are exempt from key enforcement for an account"
  type        = list(string)
  default     = null
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

variable "armed" {
  description = ""
  type        = bool
  default     = false
}

variable "email_enabled" {
  description = ""
  type        = bool
  default     = false
}

variable "s3_enabled" {
  description = ""
  type        = bool
  default     = false
}

variable "email_subject" {
  description = ""
  type        = string
}

variable "email_source" {
  description = ""
  type        = string
}

variable "admin_email" {
  description = ""
  type        = string
}

variable "email_target" {
  description = ""
  type        = string
}
