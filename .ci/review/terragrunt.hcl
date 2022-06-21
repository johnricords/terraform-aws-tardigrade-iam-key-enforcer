include {
  path = find_in_parent_folders()
}

terraform {
  source = "git::https://github.com/plus3it/terraform-aws-codecommit-flow-ci.git//modules/review?ref=4.3.3"
}

inputs = {
  environment = {
    image           = "aws/codebuild/standard:5.0"
    privileged_mode = "true"
  }

  policy_override = <<-OVERRIDE
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": "kms:Decrypt",
          "Condition": {
            "ForAnyValue:StringLike": {
              "kms:ResourceAliases": [
                "alias/aws/ssm"
              ]
            }
          },
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "AllowKmsDecryptSsm"
        },
        {
          "Action": [
            "ssm:GetParameters"
          ],
          "Effect": "Allow",
          "Resource": [
            "arn:$${partition}:ssm:$${region}:$${account_id}:parameter/codebuild/dockerhub/readonly/password",
            "arn:$${partition}:ssm:$${region}:$${account_id}:parameter/codebuild/dockerhub/readonly/username"
          ],
          "Sid": "AllowSsmRetrieve"
        }
      ]
    }
    OVERRIDE
}
