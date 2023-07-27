"""Audit Access Key Age.

Purpose:
    Reads the credential report:
    - Determines the age of each access key
    - Builds a report of all keys older than KEY_AGE_WARNING
    - Takes action (inactive/delete) on non-compliant Access Keys
Permissions:
    iam:GetCredentialReport
    iam:GetAccessKeyLastUsed
    iam:ListAccessKeys
    iam:ListGroupsForUser
    s3:putObject
    ses:SendEmail
    ses:SendRawEmail
Environment Variables:
    LOG_LEVEL: (optional): sets the level for function logging
            valid input: critical, error, warning, info (default), debug
    EMAIL_ADMIN_REPORT_ENABLED: used to enable or disable the SES emailed report
    EMAIL_SOURCE: send from address for the email, authorized in SES
    EMAIL_USER_TEMPLATE: Name of the SES template for user emails
    EMAIL_ADMIN_TEMPLATE: Name of the SES template for admin emails
    KEY_AGE_DELETE: age at which a key should be deleted (e.g. 120)
    KEY_AGE_INACTIVE: age at which a key should be inactive (e.g. 90)
    KEY_AGE_WARNING: age at which to warn (e.g. 75)
    KEY_USE_THRESHOLD: age at which unused keys should be deleted (e.g.30)
    S3_ENABLED: set to "true" and provide S3_BUCKET if the audit report
            should be written to S3
    S3_BUCKET: bucket name to write the audit report to if S3_ENABLED is
            set to "true"
Event Variables:
    armed: Set to "true" to take action on keys;
            "false" limits to reporting
    role_arn: Arn of role to assume
    account_name: AWS Account (friendly) Name
    account_number: AWS Account Number
    email_user_enabled: used to enable or disable the SES emailed report
    email_targets: default email address if event fails to pass a valid one
    exempt_groups: IAM Groups that are exempt from actions on access keys

"""
import collections
import csv
import io
import json
import logging
import os
import re
from time import sleep
import datetime
import dateutil

import boto3
from aws_assume_role_lib import assume_role, generate_lambda_session_name

# Standard logging config
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    },
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format="%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)-5s]: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").lower()],
)

log = logging.getLogger(__name__)

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
EMAIL_ADMIN_REPORT_ENABLED = (
    os.environ.get("EMAIL_ADMIN_REPORT_ENABLED", "False").lower() == "true"
)

EMAIL_SOURCE = os.environ.get("EMAIL_SOURCE")
KEY_AGE_WARNING = int(os.environ.get("KEY_AGE_WARNING", 75))
KEY_AGE_INACTIVE = int(os.environ.get("KEY_AGE_INACTIVE", 90))
KEY_AGE_DELETE = int(os.environ.get("KEY_AGE_DELETE", 120))
KEY_USE_THRESHOLD = int(os.environ.get("KEY_USE_THRESHOLD", 30))
S3_ENABLED = os.environ.get("S3_ENABLED", "False").lower() == "true"
S3_BUCKET = os.environ.get("S3_BUCKET", None)
EMAIL_TAG = os.environ.get("EMAIL_TAG", "keyenforcer:email").lower()
EMAIL_BANNER_MSG = os.environ.get("EMAIL_BANNER_MSG", "").strip()
EMAIL_BANNER_MSG_COLOR = os.environ.get("EMAIL_BANNER_MSG_COLOR", "black").strip()
EMAIL_USER_TEMPLATE = os.environ.get("EMAIL_USER_TEMPLATE")
EMAIL_ADMIN_TEMPLATE = os.environ.get("EMAIL_ADMIN_TEMPLATE")
NOT_ARMED_PREFIX = "NOT ARMED:"
ARMED_PREFIX = "ARMED:"

# Get the Lambda session and clients
SESSION = boto3.Session()
CLIENT_SES = SESSION.client("ses")
CLIENT_S3 = SESSION.client("s3")
email_regex = re.compile(
    r"([A-Za-z0-9]+[._-])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
)


class IamKeyEnforcerError(Exception):
    """All errors raised by IamKeyEnforcer Lambda."""


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Audit Access Key Age.

    Reads the credential report:
        - Determines the age of each access key
        - Builds a report of all keys older than KEY_AGE_WARNING
        - Takes action (inactive/delete) on non-compliant Access Keys
    """
    log.debug("Event:\n%s", event)

    # Assume the session
    assumed_role_session = assume_role(
        SESSION, event["role_arn"], RoleSessionName=generate_lambda_session_name()
    )

    assumed_acct_arn = assumed_role_session.client("sts").get_caller_identity()["Arn"]
    # do stuff with the assumed role using assumed_role_session
    log.debug("IAM Key Enforce account arn %s", assumed_acct_arn)

    client_iam = assumed_role_session.client("iam")

    # Generate Credential Report
    generate_credential_report(client_iam, report_counter=0)

    # Get Credential Report
    report = get_credential_report(client_iam)

    # Process Users in Credential Report
    key_report_contents = process_credential_report(client_iam, event, report)

    if key_report_contents:
        store_and_email_report(key_report_contents, event)
    else:
        log.info("No expiring access keys for account arn %s", assumed_acct_arn)


def generate_credential_report(client_iam, report_counter, max_attempts=5):
    """Generate IAM Credential Report."""
    generate_report = client_iam.generate_credential_report()

    if generate_report["State"] == "COMPLETE":
        # Report is generated, proceed in Handler
        return None

    # Report is not ready, try again
    report_counter += 1
    log.info("Generate credential report count %s", report_counter)
    if report_counter < max_attempts:
        log.info("Still waiting on report generation")
        sleep(10)
        return generate_credential_report(client_iam, report_counter)

    throttle_error = "Credential report generation throttled - exit"
    log.error(throttle_error)
    raise IamKeyEnforcerError(throttle_error)


def get_credential_report(client_iam):
    """Process IAM Credential Report."""
    credential_report = client_iam.get_credential_report()
    credential_report_csv = io.StringIO(credential_report["Content"].decode("utf-8"))
    return list(csv.DictReader(credential_report_csv))


def process_credential_report(
    client_iam, event, report
):  # pylint: disable=too-many-branches
    """Process each user and key in the Credential Report."""
    # Initialize message content
    key_report_contents = []

    # Access the credential report and process it
    for row in report:
        # A row is a unique IAM user
        user_name = row["user"]
        log.debug("Processing user: %s", user_name)

        if user_name == "<root_account>":
            log.debug("Skipping user: %s", user_name)
            continue

        # Test group exempted
        exempted = is_exempted(client_iam, user_name, event)

        # Process Access Keys for user
        access_keys = client_iam.list_access_keys(UserName=user_name)
        for key in access_keys["AccessKeyMetadata"]:
            key_age = object_age(key["CreateDate"])
            access_key_id = key["AccessKeyId"]

            # Log it
            log.info(
                "User Key Details: %s \t %s \t %s \t %s",
                user_name,
                key["AccessKeyId"],
                str(key_age),
                key["Status"],
            )

            # get time of last key use
            get_key = client_iam.get_access_key_last_used(AccessKeyId=access_key_id)

            # last_used_date value will not exist if key not used
            last_used_date = get_key["AccessKeyLastUsed"].get("LastUsedDate")

            if not exempted and not last_used_date and key_age >= KEY_USE_THRESHOLD:
                # Not Exempted and Key has not been used and
                # is older than the usage threshold, delete and report
                delete_access_key(access_key_id, user_name, client_iam, event)
                bg_color = "#E6B0AA"
                key_status = "DELETED"
            elif key_age < KEY_AGE_WARNING:
                # Key age is < warning, do nothing, continue
                continue
            elif exempted:
                # EXEMPT:, do not take action on key, but report it
                bg_color = "#D7DBDD"
                key_status = f'{key["Status"]} (Exempt)'
            elif key_age >= KEY_AGE_DELETE:
                # NOT EXEMPT: Delete and report
                delete_access_key(access_key_id, user_name, client_iam, event)
                bg_color = "#E6B0AA"
                key_status = "DELETED"
            elif key_age >= KEY_AGE_INACTIVE:
                # NOT EXEMPT: Disable and report
                disable_access_key(access_key_id, user_name, client_iam, event)
                bg_color = "#F4D03F"
                key_status = key["Status"]
            else:
                # NOT EXEMPT: Report
                bg_color = "#FFFFFF"
                key_status = key["Status"]

            key_report_contents.append(
                {
                    "bg_color": bg_color,
                    "user_name": user_name,
                    "access_key_id": key["AccessKeyId"],
                    "key_age": str(key_age),
                    "key_status": key_status,
                    "last_used_date": str(last_used_date),
                }
            )

    return key_report_contents


def is_exempted(client_iam, user_name, event):
    """Determine if user is in an exempted group."""
    groups = client_iam.list_groups_for_user(UserName=user_name)
    for group in groups["Groups"]:
        if group["GroupName"] in event["exempt_groups"]:
            log.info("User is exempt via group membership in: %s", group["GroupName"])
            return True
    return False


def delete_access_key(access_key_id, user_name, client_iam, event):
    """Delete Access Key."""
    armed_log_prefix = NOT_ARMED_PREFIX
    if event["armed"]:
        armed_log_prefix = ARMED_PREFIX
    log.info(
        "%s Deleting AccessKeyId %s for user %s",
        armed_log_prefix,
        access_key_id,
        user_name,
    )
    if event["armed"]:
        client_iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)

    if event["email_user_enabled"]:
        armed_state_msg = (
            "has been deleted" if event["armed"] else "is marked for deletion"
        )
        email_user(
            client_iam,
            {
                "armed_state_msg": armed_state_msg,
                "access_key_id": access_key_id,
                "action": "deleted",
                "key_age": KEY_AGE_DELETE,
                "user_name": user_name,
            },
            event,
        )
    else:
        log.info("Email User not enabled per event email_user_enabled variable setting")


def disable_access_key(access_key_id, user_name, client_iam, event):
    """Disable Access Key."""
    armed_log_prefix = NOT_ARMED_PREFIX
    if event["armed"]:
        armed_log_prefix = ARMED_PREFIX
    log.info(
        "%s Disabling AccessKeyId %s for user %s",
        armed_log_prefix,
        access_key_id,
        user_name,
    )

    if event["armed"]:
        client_iam.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )

    if event["email_user_enabled"]:
        armed_state_msg = (
            "has been marked 'Inactive'"
            if event["armed"]
            else "would be marked 'Inactive'"
        )
        email_user(
            client_iam,
            {
                "armed_state_msg": armed_state_msg,
                "access_key_id": access_key_id,
                "action": "disabled",
                "key_age": KEY_AGE_INACTIVE,
                "user_name": user_name,
            },
            event,
        )
    else:
        log.info("Email User not enabled per event email_user_enabled variable setting")


def email_user(client_iam, user_key_details, event):
    """Email user."""
    to_addresses = get_to_addresses(event)
    user_email = get_user_email(client_iam, user_key_details["user_name"], event)
    if user_email:
        to_addresses.append(user_email)

    if not to_addresses:
        log.error("User email list is empty, no emails sent")
        return

    template_data = user_email_template_data(user_key_details, event)

    send_email(EMAIL_USER_TEMPLATE, template_data, to_addresses)


def email_admin(event, template_data):
    """Email admin."""
    to_addresses = get_to_addresses(event)

    if not to_addresses:
        log.error("Admin email list is empty, no emails sent")
        return

    # Construct and Send Email
    send_email(
        EMAIL_ADMIN_TEMPLATE,
        template_data,
        to_addresses,
    )


def get_to_addresses(event):
    """Get the addresses to send the user email to."""
    to_addresses = []

    if validate_email(ADMIN_EMAIL):
        to_addresses.append(ADMIN_EMAIL)
    else:
        log_invalid_email("admin", ADMIN_EMAIL)

    event_email_targets = get_event_email_targets(event)
    to_addresses.extend(event_email_targets)

    return to_addresses


def get_event_email_targets(event):
    """Get list of email targets from the provided event."""
    email_targets = []
    for email_target in event["email_targets"]:
        if validate_email(email_target):
            email_targets.append(email_target)
        else:
            log_invalid_email("target", email_target)

    # if mode is debug we do not want to email the actual targets
    # log whatever targets there were and return an empty list
    if event.get("debug") and email_targets:
        log.debug("Debug Mode:Event email targets %s", ", ".join(email_targets))
        return []
    return email_targets


def get_user_email(client_iam, user_name, event):
    """Get and validate user email from Key Tags."""
    tags = client_iam.list_user_tags(UserName=user_name)
    email = None
    for tag in tags["Tags"]:
        if tag["Key"].lower() == EMAIL_TAG:
            email = tag["Value"]
            break

    if not email:
        log.debug("No email found for user %s", user_name)
        return None

    if validate_email(email):
        if not event.get("debug"):
            return email
        log.debug("Debug Mode: Append user email %s", email)
    else:
        log_invalid_email(f"user ({user_name})", email)

    return None


def log_invalid_email(email_type, email):
    """Log error for invalid email and specify the type."""
    log.error("Invalid %s email found - email: %s", email_type, email)


def validate_email(email):
    """Validate email provided matches regex."""
    if not email or not re.fullmatch(email_regex, email):
        return False

    return True


def admin_email_template_data(key_report_contents, event, exempt_groups):
    """Build email template data for admin emails."""
    template_data = {
        "account_number": event["account_number"],
        "account_name": event["account_name"],
        "key_report_contents": key_report_contents,
        "key_age_inactive": KEY_AGE_INACTIVE,
        "key_age_delete": KEY_AGE_DELETE,
        "key_age_warning": KEY_AGE_WARNING,
    }

    template_data.update(optional_email_template_data(event, exempt_groups))
    return template_data


def user_email_template_data(user_email_details, event):
    """Build email template data for user emails."""
    template_data = {
        "armed_state_msg": user_email_details["armed_state_msg"],
        "access_key_id": user_email_details["access_key_id"],
        "action": user_email_details["action"],
        "key_age": user_email_details["key_age"],
        "user_name": user_email_details["user_name"],
    }
    template_data.update(optional_email_template_data(event))
    return template_data


def optional_email_template_data(event, exempt_groups=None):
    """Set and return optional email template data."""
    template_data = {}
    if EMAIL_BANNER_MSG:
        template_data["email_banner_msg"] = EMAIL_BANNER_MSG
        template_data["email_banner_msg_color"] = EMAIL_BANNER_MSG_COLOR

    if not event["armed"]:
        template_data["unarmed"] = True

    if exempt_groups:
        template_data["exempt_groups"] = exempt_groups

    return template_data


def store_and_email_report(key_report_contents, event):
    """Generate HTML and send report to email_targets list for tenant \
    account and ADMIN_EMAIL via SES."""
    if not S3_ENABLED:
        log.info("S3 report not enabled per setting")

    if not EMAIL_ADMIN_REPORT_ENABLED:
        log.info("Admin Email not enabled per setting")

    if not (S3_ENABLED and EMAIL_ADMIN_REPORT_ENABLED):
        return

    exempt_groups = (
        ", ".join(event["exempt_groups"]) if event["exempt_groups"] else None
    )

    template_data = admin_email_template_data(key_report_contents, event, exempt_groups)

    store_in_s3(event["account_number"], template_data)

    email_admin(event, template_data)


def store_in_s3(account_number, template_data):
    """Store email report in S3 Bucket."""
    s3_key = (
        f"{account_number}"
        "/access_key_audit_report_"
        f"{str(datetime.date.today())}.html"
    )

    response = CLIENT_SES.test_render_template(
        TemplateName=EMAIL_ADMIN_TEMPLATE, TemplateData=json.dumps(template_data)
    )

    email_contents = response.get("RenderedTemplate", None)

    if email_contents:
        log.debug(
            "Storing report to S3 key %s Report Details: %s", s3_key, email_contents
        )
        response = CLIENT_S3.put_object(
            Bucket=S3_BUCKET, Key=s3_key, Body=email_contents
        )
    else:
        log.error(
            "Error generating S3 report using TemplateName: %s and TemplateData: %s",
            EMAIL_ADMIN_TEMPLATE,
            template_data,
        )


def send_email(template, template_data, email_targets):
    """Email user with the action taken on their key."""
    if not email_targets:
        log.error("Email targets list is empty, no emails sent")
        return

    response = CLIENT_SES.send_templated_email(
        Source=EMAIL_SOURCE,
        Destination={
            "ToAddresses": email_targets,
        },
        Template=template,
        TemplateData=json.dumps(template_data),
    )

    log.info("Email Sent Successfully. Message ID: %s", response["MessageId"])


def object_age(last_changed):
    """Determine days since last change."""
    # Handle as string
    if isinstance(last_changed, str):
        last_changed_date = dateutil.parser.parse(last_changed).date()
    # Handle as native datetime
    elif isinstance(last_changed, datetime.datetime):
        last_changed_date = last_changed.date()
    else:
        return 0
    age = datetime.date.today() - last_changed_date
    return age.days
