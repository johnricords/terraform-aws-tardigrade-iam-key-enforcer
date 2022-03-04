remote_state {
  backend = "s3"

  config = {
    bucket         = "${local.repo_name}-ci-tfstate"
    dynamodb_table = "${local.repo_name}-ci-tfstate-lock"
    encrypt        = true
    key            = "tfstate/${path_relative_to_include()}/terraform.tfstate"
    region         = get_env("AWS_DEFAULT_REGION")

    dynamodb_table_tags = local.tags
    s3_bucket_tags      = local.tags
  }

  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

terraform {
  before_hook "terraform_lock" {
    commands = ["init"]
    execute  = ["rm", "-f", ".terraform.lock.hcl"]
  }

  after_hook "terraform_lock" {
    commands = concat(get_terraform_commands_that_need_locking(), ["init"])
    execute  = ["rm", "-f", "${get_terragrunt_dir()}/.terraform.lock.hcl"]
  }
}

locals {
  repo_name = basename(abspath("${get_parent_terragrunt_dir()}/..")) # e.g. "dicelab-repo-template"

  tags = {
    RepoCloneUrl     = "https://git-codecommit.us-east-1.amazonaws.com/v1/repos/${local.repo_name}"
    RepoConsoleUrl   = "https://console.aws.amazon.com/codesuite/codecommit/repositories/${local.repo_name}"
    RepoName         = local.repo_name
    TfstateBucket    = "${local.repo_name}-ci-tfstate"
    TfstateLockTable = "${local.repo_name}-ci-tfstate-lock"
  }
}

inputs = {
  repo_name = local.repo_name
  tags      = local.tags
}
