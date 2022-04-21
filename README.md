# Tardigrade IAM Key Enforcer

This repo contains the Python-based Lambda function that will audit IAM Access keys for an account and will enforce key rotation as well as notify users.

## Basic Function

The Lambda function is triggered for each account by an Event notification that is configured to run on a schedule.
The function audits each user in an account for access keys and determines how long before they expire, it will then notify users that their key expires in X days and that automatic key enforcement is forthcoming.

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 3.0 |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.iam_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_admin_email"></a> [admin\_email](#input\_admin\_email) | Admin Email that will receive all emails and reports about actions taken if email is enabled | `string` | n/a | yes |
| <a name="input_email_source"></a> [email\_source](#input\_email\_source) | Email that will be used to send messages | `string` | n/a | yes |
| <a name="input_key_age_delete"></a> [key\_age\_delete](#input\_key\_age\_delete) | Age at which a key should be deleted (e.g. 120) | `number` | n/a | yes |
| <a name="input_key_age_inactive"></a> [key\_age\_inactive](#input\_key\_age\_inactive) | Age at which a key should be inactive (e.g. 90) | `number` | n/a | yes |
| <a name="input_key_age_warning"></a> [key\_age\_warning](#input\_key\_age\_warning) | Age at which to warn (e.g. 75) | `number` | n/a | yes |
| <a name="input_key_use_threshold"></a> [key\_use\_threshold](#input\_key\_use\_threshold) | Age at which unused keys should be deleted (e.g.30) | `number` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name to prefix resources with | `string` | n/a | yes |
| <a name="input_accounts"></a> [accounts](#input\_accounts) | List of account objects to create events for | <pre>list(object({<br>    account_name       = string<br>    account_number     = string<br>    role_name          = string<br>    armed              = bool<br>    email_user_enabled = bool<br>    email_target       = list(string)<br>    exempt_groups      = list(string)<br>  }))</pre> | `[]` | no |
| <a name="input_assume_role_name"></a> [assume\_role\_name](#input\_assume\_role\_name) | Name of the IAM role that the lambda will assume in the target account | `string` | `"E_IAM_KEY_ENFORCER"` | no |
| <a name="input_compatible_python_runtimes"></a> [compatible\_python\_runtimes](#input\_compatible\_python\_runtimes) | Compatible version of python to use defaults to 3.8 | `list(string)` | <pre>[<br>  "python3.8"<br>]</pre> | no |
| <a name="input_email_admin_report_enabled"></a> [email\_admin\_report\_enabled](#input\_email\_admin\_report\_enabled) | Used to enable or disable the SES emailed report | `bool` | `false` | no |
| <a name="input_email_admin_report_subject"></a> [email\_admin\_report\_subject](#input\_email\_admin\_report\_subject) | Subject of the report email that is sent | `string` | `null` | no |
| <a name="input_email_tag"></a> [email\_tag](#input\_email\_tag) | Tag to be placed on the IAM user that we can use to notify when their key is going to be disabled/deleted | `string` | `"keyenforcer:email"` | no |
| <a name="input_log_level"></a> [log\_level](#input\_log\_level) | Log level for lambda | `string` | `"INFO"` | no |
| <a name="input_s3_bucket"></a> [s3\_bucket](#input\_s3\_bucket) | Bucket name to write the audit report to if s3\_enabled is set to 'true' | `string` | `null` | no |
| <a name="input_s3_enabled"></a> [s3\_enabled](#input\_s3\_enabled) | Set to 'true' and provide s3\_bucket if the audit report should be written to S3 | `bool` | `false` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | Schedule Expressions for Rules | `string` | `"cron(0 1 ? * SUN *)"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags for resource | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_lambda"></a> [lambda](#output\_lambda) | The lambda module object |

<!-- END TFDOCS -->
