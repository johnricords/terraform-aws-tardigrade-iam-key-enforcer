data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

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
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v4.12.1"

  build_in_docker     = false
  compatible_runtimes = var.compatible_python_runtimes
  description         = "Lambda function for Key Enforcement"
  function_name       = "${var.project_name}-iam-key-enforcer"
  handler             = "iam_key_enforcer.lambda_handler"
  runtime             = "python3.8"
  tags                = var.tags
  timeout             = 300

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda.json

  ignore_source_code_hash  = true
  recreate_missing_package = false

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
    EMAIL_BANNER_MSG           = var.email_banner_message
    EMAIL_BANNER_MSG_COLOR     = var.email_banner_message_color
  }

  source_path = [
    {
      path          = "${path.module}/src/python",
      prefix_in_zip = ""
      patterns      = ["!\\.terragrunt-source-manifest"]
    },
    {
      pip_requirements = "${path.module}/src/requirements.txt",
      prefix_in_zip    = ""
    }
  ]
}


resource "aws_lambda_permission" "this" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/${var.project_name}-*"
}


locals {
  has_accounts = length(var.accounts) > 0 ? 1 : 0
}

##############################
# SQS Queue Policy
##############################
resource "aws_sqs_queue_policy" "this" {
  queue_url = aws_sqs_queue.this.id
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
          Resource  = aws_sqs_queue.this.arn,
          Condition = {
            "ArnLike" : {
              "aws:SourceArn" : "arn:${data.aws_partition.current.partition}:events:*:*:rule/${var.project_name}*"
            }
          }
        },
        {
          Sid    = "AllowRead",
          Effect = "Allow",
          "Principal" : {
            "AWS" : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
          },
          Action   = "sqs:ReceiveMessage",
          Resource = aws_sqs_queue.this.arn,
        }
      ]
    }
  )
}

##############################
# SQS Queue
##############################
resource "aws_sqs_queue" "this" {
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
      "iam:ListAccessKeys",
      "iam:ListUserTags",
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

  for_each = { for account in var.accounts : account.account_name => account }

  event_name             = "${var.project_name}-${each.value.account_name}"
  event_rule_description = "Scheduled Event that runs IAM Key Enforcer Lambda for account ${each.value.account_number} - ${each.value.account_name}"
  lambda_arn             = module.lambda.lambda_function_arn
  schedule_expression    = var.schedule_expression
  input_transformer = {
    input_template = jsonencode({
      "account_number" : each.value.account_number,
      "account_name" : each.value.account_name,
      "role_arn" : "arn:${data.aws_partition.current.partition}:iam::${each.value.account_number}:role/${each.value.role_name}",
      "armed" : each.value.armed,
      "email_targets" : each.value.email_targets,
      "exempt_groups" : each.value.exempt_groups,
      "email_user_enabled" : each.value.email_user_enabled,
    })
  }
  tags = var.tags
  dead_letter_config = {
    arn = aws_sqs_queue.this.arn
  }
}
