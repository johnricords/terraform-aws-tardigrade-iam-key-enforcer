resource "aws_cloudwatch_event_rule" "this" {
  name                = "${var.project_name}-${var.event_name}"
  description         = var.event_rule_description
  tags                = var.tags
  event_bus_name      = var.event_bus_name
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "this" {
  event_bus_name = var.event_bus_name
  arn            = var.lambda_arn
  rule           = aws_cloudwatch_event_rule.this.name

  dynamic "input_transformer" {
    for_each = var.input_transformer != null ? [var.input_transformer] : []
    content {
      input_template = input_transformer.value.input_template
    }
  }

  dynamic "dead_letter_config" {
    for_each = var.dead_letter_config != null ? [var.dead_letter_config] : []
    content {
      arn = dead_letter_config.value.arn
    }
  }
}
