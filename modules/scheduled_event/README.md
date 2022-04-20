<!-- BEGIN TFDOCS -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Resources

| Name | Type |
|------|------|

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_event_name"></a> [event\_name](#input\_event\_name) | Name of the event | `string` | n/a | yes |
| <a name="input_event_rule_description"></a> [event\_rule\_description](#input\_event\_rule\_description) | Description of what the event rule does | `string` | n/a | yes |
| <a name="input_lambda_arn"></a> [lambda\_arn](#input\_lambda\_arn) | ARN of the target lambda | `string` | n/a | yes |
| <a name="input_lambda_name"></a> [lambda\_name](#input\_lambda\_name) | Name of the target lambda | `string` | n/a | yes |
| <a name="input_dead_letter_config"></a> [dead\_letter\_config](#input\_dead\_letter\_config) | Configuration of the dead letter queue | <pre>object({<br>    arn = string<br>  })</pre> | `null` | no |
| <a name="input_event_bus_name"></a> [event\_bus\_name](#input\_event\_bus\_name) | EventBridge event bus | `string` | `"default"` | no |
| <a name="input_input_transformer"></a> [input\_transformer](#input\_input\_transformer) | Transform to apply on the event input | <pre>object({<br>    input_template = string<br>  })</pre> | `null` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | Schedule Expression for scheduled event | `string` | `"cron(0 0 * * 1 *)"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to the module resources | `map(string)` | `{}` | no |

## Outputs

No outputs.

<!-- END TFDOCS -->