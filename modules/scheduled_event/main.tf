data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "this" {}

resource "aws_cloudwatch_event_rule" "this" {
  name                = var.event_name
  description         = var.event_rule_description
  tags                = var.tags
  event_bus_name      = var.event_bus_name
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "this" {
  event_bus_name = var.event_bus_name
  arn            = "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.this.account_id}:function:${var.lambda_name}"
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

resource "aws_lambda_permission" "this" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
