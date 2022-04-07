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
