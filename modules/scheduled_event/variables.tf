variable "event_bus_name" {
  description = "EventBridge event bus"
  type        = string
  default     = "default"
}

variable "event_rule_description" {
  description = "Description of what the event rule does"
  type        = string
}

variable "event_name" {
  description = "Name of the event"
  type        = string
}

variable "lambda_name" {
  description = "Name of the target lambda"
  type        = string
}

variable "lambda_arn" {
  description = "ARN of the target lambda"
  type        = string
}

variable "schedule_expression" {
  description = "Schedule Expression for scheduled event"
  type        = string
  default     = "cron(0 0 * * 1 *)"
}

variable "input_transformer" {
  description = "Transform to apply on the event input"
  type = object({
    input_template = string
  })
  default = null
}

variable "dead_letter_config" {
  description = "Configuration of the dead letter queue"
  type = object({
    arn = string
  })
  default = null
}

variable "tags" {
  description = "A map of tags to add to the module resources"
  type        = map(string)
  default     = {}
}


