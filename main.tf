data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AllowS3Object"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::${var.s3_bucket}/*"]
  }
  statement {
    actions = [
      "ses:SendEmail"
    ]
    resources = [
      "*"
    ]
  }
  statement {
    sid = "AllowAssumeRole"
    actions = [
      "sts:AssumeRole"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:iam::*:role/${var.assume_role_name}"
    ]
  }
}

module "lambda" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v2.34.1"

  function_name       = "${var.project_name}-iam-key-enforcer"
  description         = "Lambda function for Key Enforcement"
  handler             = "iam-key-enforcer.lambda_handler"
  attach_policy_json  = true
  policy_json         = data.aws_iam_policy_document.lambda.json
  runtime             = "python3.8"
  compatible_runtimes = var.compatible_python_runtimes
  timeout             = 300
  tags                = var.tags
  environment_variables = {
    LOG_LEVEL                  = var.log_level
    EMAIL_ADMIN_REPORT_ENABLED = var.email_admin_report_enabled
    EMAIL_ADMIN_REPORT_SUBJECT = var.email_admin_report_subject
    EMAIL_SOURCE               = var.email_source
    ADMIN_EMAIL                = var.admin_email
    KEY_AGE_WARNING            = var.key_age_warning
    KEY_AGE_INACTIVE           = var.key_age_inactive
    KEY_AGE_DELETE             = var.key_age_delete
    KEY_USE_THRESHOLD          = var.key_use_threshold
    S3_ENABLED                 = var.s3_enabled
    S3_BUCKET                  = var.s3_bucket
    EMAIL_TAG                  = var.email_tag
  }

  source_path = [
    {
      path          = "${path.module}/src/python",
      prefix_in_zip = ""
    },
    {
      pip_requirements = "${path.module}/src/requirements.txt",
      prefix_in_zip    = ""
    }
  ]

  build_in_docker = false
}


locals {
  has_accounts = length(var.accounts) > 0 ? 1 : 0
}

##############################
# SQS Queue Policy
##############################
resource "aws_sqs_queue_policy" "this" {
  count     = local.has_accounts
  queue_url = aws_sqs_queue.this[0].id
  policy = jsonencode(
    {
      Version = "2012-10-17",
      Id      = "sqspolicy",
      Statement : [
        {
          Sid       = "AllowSend",
          Effect    = "Allow",
          Principal = "*",
          Action    = "sqs:SendMessage",
          Resource  = aws_sqs_queue.this[0].arn,
          Condition = {
            "ArnEquals" : {
              "aws:SourceArn" : "arn:${data.aws_partition.current.partition}:events:*:*:rule/${var.project_name}*"
            }
          }
        },
        {
          Sid    = "AllowRead",
          Effect = "Allow",
          "Principal" : {
            "AWS" : [
              data.aws_caller_identity.current.account_id
            ]
          },
          Action   = "sqs:ReceiveMessage",
          Resource = aws_sqs_queue.this[0].arn,
        }
      ]
    }
  )
}

##############################
# SQS Queue
##############################
resource "aws_sqs_queue" "this" {
  count                      = local.has_accounts
  name                       = "${var.project_name}-iam-key-enforcer-dlq"
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = 30
  tags                       = var.tags
}

##############################
# Policy
##############################
data "aws_iam_policy_document" "iam_key" {
  count = local.has_accounts
  statement {
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:ListUsers",
      "iam:GetAccessKeyLastUsed"
    ]

    resources = [
      "*"
    ]
  }

  statement {
    actions = [
      "iam:DeleteAccessKey",
      "iam:ListGroupsForUser",
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys"
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:iam::*:user/*"
    ]
  }
}

resource "aws_iam_policy" "iam_policy" {
  count = local.has_accounts
  name  = "${var.project_name}-iam-key-enforcer-iam-policy"

  policy = data.aws_iam_policy_document.iam_key[0].json
}

resource "aws_iam_role" "assume_role" {
  count = local.has_accounts
  name  = var.assume_role_name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Sid" : "AssumeRoleCrossAccount",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = [aws_iam_policy.iam_policy[0].arn]
}



##############################
# Schedule Event for testing
##############################
module "scheduled_events" {
  source = "./modules/scheduled_event"

  for_each = { for account in var.accounts : account.account_number => account }

  event_name             = "${var.project_name}-${each.value.account_name}"
  event_rule_description = "Scheduled Event that runs IAM Key Enforcer Lambda for account ${each.value.account_number} - ${each.value.account_name}"
  lambda_arn             = module.lambda.lambda_function_arn
  lambda_name            = module.lambda.lambda_function_name
  schedule_expression    = var.schedule_expression
  input_transformer = {
    input_template = jsonencode({
      "account_number" : each.value.account_number,
      "account_name" : each.value.account_name,
      "role_arn" : aws_iam_role.assume_role[0].arn,
      "armed" : each.value.armed,
      "email_target" : each.value.email_target,
      "exempt_groups" : each.value.exempt_groups,
      "email_user_enabled" : each.value.email_user_enabled,
    })
  }
  tags = var.tags
  dead_letter_config = {
    arn = aws_sqs_queue.this[0].arn
  }
}

