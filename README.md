# Terraform AWS Tardigrade IAM Key Enforcer
This repo contains the Python-based Lambda function that will audit IAM Access keys for an account and will enforce key rotation as well as notify users.

## Basic Function
The Lambda function is triggered for each account by an Event notification that is configured to run on a schedule.
The function audits each user in an account for access keys and determines how long before they expire, it will then notify users that their key expires in X days and that automatic key enforcement is forthcoming.

