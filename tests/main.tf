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

module "iam_key_enforcer" {
  source = "../"

  project_name = local.project

  assume_role_name = aws_iam_role.assume_role.name

  log_level                  = "DEBUG"
  email_admin_report_enabled = true
  email_admin_report_subject = "Test IAM Key Enforcement Report"
  email_source               = var.email_source
  email_banner_message       = "IAM Key Enforcement will be armed on 07/01/2022"
  email_banner_message_color = "red"
  admin_email                = var.admin_email
  key_age_warning            = var.key_age_warning
  key_age_inactive           = var.key_age_inactive
  key_age_delete             = var.key_age_delete
  key_use_threshold          = var.key_use_threshold
  s3_enabled                 = var.s3_enabled
  s3_bucket                  = aws_s3_bucket.this.id
  tags                       = local.tags

  accounts = [
    {
      account_name        = var.account_name
      account_number      = data.aws_caller_identity.current.account_id
      armed               = false
      debug               = true
      email_user_enabled  = true
      email_targets       = [var.email_target]
      exempt_groups       = var.exempt_groups
      schedule_expression = "rate(5 minutes)"
    }
  ]
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

data "aws_iam_policy_document" "iam_key" {
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
  name = "${local.project}-iam-key-enforcer-iam-policy"

  policy = data.aws_iam_policy_document.iam_key.json
}

resource "aws_iam_role" "assume_role" {
  name                = "${local.project}-iam-key-enforcer-role"
  managed_policy_arns = [aws_iam_policy.iam_policy.arn]

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
}

data "terraform_remote_state" "prereq" {
  backend = "local"
  config = {
    path = "prereq/terraform.tfstate"
  }
}
