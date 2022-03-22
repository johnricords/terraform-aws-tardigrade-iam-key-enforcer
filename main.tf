data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AllowS3Object"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
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
      var.policy_assume_role_arn
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
    LOG_LEVEL         = var.log_level
    EMAIL_ENABLED     = var.email_enabled
    EMAIL_SUBJECT     = var.email_subject
    EMAIL_SOURCE      = var.email_source
    ADMIN_EMAIL       = var.admin_email
    KEY_AGE_WARNING   = var.key_age_warning
    KEY_AGE_INACTIVE  = var.key_age_inactive
    KEY_AGE_DELETE    = var.key_age_delete
    KEY_USE_THRESHOLD = var.key_use_threshold
    S3_ENABLED        = var.s3_enabled
    S3_BUCKET         = var.s3_bucket
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
  name                       = var.sqs_queue_name
  message_retention_seconds  = var.message_retention_seconds
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = var.visibility_timeout_seconds
  tags                       = var.tags
}


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
      "ACCOUNT_NUMBER" : each.value.account_number,
      "ACCOUNT_NAME" : each.value.account_name,
      "ROLE_ARN" : each.value.role_arn,
      "ARMED" : each.value.armed,
      "EMAIL_TARGET" : each.value.email_target,
      "EXEMPT_GROUPS" : each.value.exempt_groups,
      "EMAIL_USER_ENABLED" : each.value.email_user_enabled,
    })
  }
  tags = var.tags
  dead_letter_config = {
    arn = aws_sqs_queue.this.arn
  }
}

data "terraform_remote_state" "prereq" {
  backend = "local"
  config = {
    path = "prereq/terraform.tfstate"
  }
}
