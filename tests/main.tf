terraform {
  required_version = ">= 0.12"
}

locals {
  id      = data.terraform_remote_state.prereq.outputs.test_id.result
  project = "${var.project}-${local.id}"

  tags = {
    "broker_managed" = var.broker_managed
    "contact"        = var.contact_email
    "project"        = local.project
  }
}

module "iam_key_enforcer" {
  source = "../"

  project_name = local.project
}
