terraform {
  required_version = ">= 0.12"
}

data "aws_iam_policy_document" "lambda" {
  statement {
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport"
    ]

    resources = [
      "*"
    ]
  }

}

module "lambda" {
  source = "git::https://github.com/plus3it/terraform-aws-lambda.git?ref=v1.3.0"

  function_name = "${var.project_name}-iam-key-enforcer"
  description   = "Lambda function for Key Enforcement"
  handler       = "main.lambda_handler"
  policy        = data.aws_iam_policy_document.lambda
  runtime       = "python3.8"
  source_path   = "${path.module}/iam-key-enforcer.py"
  timeout       = 300

  environment = {
    variables = {
      ACCOUNT_NUMBER   = var.account_number
      ACCOUNT_NAME     = var.account_name
      KEY_AGE_WARNING  = var.key_age_warning
      KEY_AGE_INACTIVE = var.key_age_inactive
      KEY_AGE_DELETE   = var.key_age_delete
      EXEMPT_GROUP     = var.exempt_group
      LOG_LEVEL        = var.log_level
      ARMED            = var.armed
      EMAIL_ENABLED    = var.email_enabled
      S3_ENABLED       = var.s3_enabled
      EMAIL_SUBJECT    = var.email_subject
      EMAIL_SOURCE     = var.email_source
      ADMIN_EMAIL      = var.admin_email
      EMAIL_TARGET     = var.email_target
    }
  }
}


data "terraform_remote_state" "prereq" {
  backend = "local"
  config = {
    path = "prereq/terraform.tfstate"
  }
}
