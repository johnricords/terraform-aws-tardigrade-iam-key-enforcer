data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  id      = data.terraform_remote_state.prereq.outputs.test_id.result
  project = "${var.project}-${local.id}"

  tags = {
    "broker_managed" = true
    "contact"        = var.contact_email
    "project"        = local.project
  }
}

##################### Test Resources ###############
data "aws_iam_policy_document" "iam_key" {
  statement {
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "iam:ListUsers",
      "iam:GetAccessKeyLastUsed",
      "ses:SendEmail"
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
      "arn:aws:iam::*:user/*"
    ]
  }
}

resource "aws_iam_policy" "iam_policy" {
  name = "${local.project}-iam-key-enforcer-iam-policy"

  policy = data.aws_iam_policy_document.iam_key.json
}

resource "aws_iam_role" "cross_account" {
  name = "${local.project}-iam-key-enforcer-role"
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
  managed_policy_arns = [aws_iam_policy.iam_policy.arn]
}

resource "aws_s3_bucket" "this" {
  bucket        = "${local.project}-iam-key-enforcer-test-bucket"
  tags          = local.tags
  force_destroy = true

}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
            "ArnEquals" : {
              "aws:SourceArn" : "arn:${data.aws_partition.current.partition}:events:*:*:rule/${local.project}*"
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
  name                       = "${local.project}-iam-key-enforcer-dlq"
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = 30
  tags                       = local.tags
}

locals {
  accounts = [
    {
      account_name       = var.account_name
      account_number     = data.aws_caller_identity.current.account_id
      role_arn           = aws_iam_role.cross_account.arn
      armed              = false
      email_user_enabled = true
      email_target       = [var.email_target]
      exempt_groups      = var.exempt_groups
    }
  ]
}

##############################
# Schedule Event for testing
##############################
module "scheduled_events" {
  source = "../modules/scheduled_event"

  for_each = { for account in local.accounts : account.account_number => account }

  event_name             = "${local.project}-${each.value.account_name}"
  event_rule_description = "Scheduled Event that runs IAM Key Enforcer Lambda for account ${each.value.account_number} - ${each.value.account_name}"
  lambda_arn             = module.iam_key_enforcer.lambda.lambda_function_arn
  lambda_name            = module.iam_key_enforcer.lambda.lambda_function_name
  schedule_expression    = var.schedule_expression
  input_transformer = {
    input_template = jsonencode({
      "account_number" : each.value.account_number,
      "account_name" : each.value.account_name,
      "role_arn" : each.value.role_arn,
      "armed" : each.value.armed,
      "email_target" : each.value.email_target,
      "exempt_groups" : each.value.exempt_groups,
      "email_user_enabled" : each.value.email_user_enabled,
    })
  }
  tags = local.tags
  dead_letter_config = {
    arn = aws_sqs_queue.this.arn
  }
}

##################### End Test Resources ###############

module "iam_key_enforcer" {
  source = "../"

  project_name = local.project

  assume_role_name = "${local.project}-iam-key-enforcer-role"

  log_level         = "DEBUG"
  email_enabled     = true
  email_subject     = "Test IAM Key Enforcement Report"
  email_source      = var.email_source
  admin_email       = var.admin_email
  key_age_warning   = var.key_age_warning
  key_age_inactive  = var.key_age_inactive
  key_age_delete    = var.key_age_delete
  key_use_threshold = var.key_use_threshold
  s3_enabled        = var.s3_enabled
  s3_bucket         = aws_s3_bucket.this.id
  s3_bucket_arn     = aws_s3_bucket.this.arn

  tags = local.tags
}


data "terraform_remote_state" "prereq" {
  backend = "local"
  config = {
    path = "prereq/terraform.tfstate"
  }
}
