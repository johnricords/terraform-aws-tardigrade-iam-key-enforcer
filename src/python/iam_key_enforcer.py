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
    EMAIL_ADMIN_REPORT_SUBJECT: subject line for the email
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
EMAIL_ADMIN_REPORT_SUBJECT = os.environ.get("EMAIL_ADMIN_REPORT_SUBJECT")
EMAIL_SOURCE = os.environ.get("EMAIL_SOURCE")
KEY_AGE_WARNING = int(os.environ.get("KEY_AGE_WARNING", 75))
KEY_AGE_INACTIVE = int(os.environ.get("KEY_AGE_INACTIVE", 90))
KEY_AGE_DELETE = int(os.environ.get("KEY_AGE_DELETE", 120))
KEY_USE_THRESHOLD = int(os.environ.get("KEY_USE_THRESHOLD", 30))
S3_ENABLED = os.environ.get("S3_ENABLED", "False").lower() == "true"
S3_BUCKET = os.environ.get("S3_BUCKET", None)
EMAIL_TAG = os.environ.get("EMAIL_TAG", "keyenforcer:email").lower()

# Get the Lambda session
SESSION = boto3.Session()

email_regex = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
)


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Audit Access Key Age.

    Reads the credential report:
        - Determines the age of each access key
        - Builds a report of all keys older than KEY_AGE_WARNING
        - Takes action (inactive/delete) on non-compliant Access Keys
    """
    log.debug("Event:\n%s", event)

    # Get the config
    role_arn = event["role_arn"]
    role_session_name = generate_lambda_session_name()  # see below for details

    # Assume the session
    assumed_role_session = assume_role(
        SESSION, role_arn, RoleSessionName=role_session_name
    )

    # do stuff with the Lambda role using SESSION
    log.debug(SESSION.client("sts").get_caller_identity()["Arn"])

    # do stuff with the assumed role using assumed_role_session
    log.debug(assumed_role_session.client("sts").get_caller_identity()["Arn"])

    client_iam = assumed_role_session.client("iam")
    client_ses = SESSION.client("ses")

    # Generate Credential Report
    generate_credential_report(client_iam, report_counter=0)

    # Get Credential Report
    report = get_credential_report(client_iam)

    # Process Users in Credential Report
    body = process_users(client_iam, client_ses, event, report)

    # Process message for SES
    process_message(body, event)


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
    raise Exception(throttle_error)


def get_credential_report(client_iam):
    """Process IAM Credential Report."""
    credential_report = client_iam.get_credential_report()
    credential_report_csv = io.StringIO(credential_report["Content"].decode("utf-8"))
    return list(csv.DictReader(credential_report_csv))


def process_users(
    client_iam, client_ses, event, report
):  # pylint: disable=too-many-branches
    """Process each user and key in the Credential Report."""
    # Initialize message content
    html_body = ""

    # Access the credential report and process it
    for row in report:
        line = ""
        # A row is a unique IAM user
        user_name = row["user"]
        log.debug("Processing user: %s", user_name)

        if user_name == "<root_account>":
            continue

        # Test group exempted
        exempted = is_exempted(client_iam, user_name, event)

        # Process Access Keys for user
        access_keys = client_iam.list_access_keys(UserName=user_name)
        for key in access_keys["AccessKeyMetadata"]:
            key_age = object_age(key["CreateDate"])
            access_key_id = key["AccessKeyId"]

            # get time of last key use
            get_key = client_iam.get_access_key_last_used(AccessKeyId=access_key_id)

            # last_used_date value will not exist if key not used
            last_used_date = get_key["AccessKeyLastUsed"].get("LastUsedDate")

            if not last_used_date and key_age >= KEY_USE_THRESHOLD and not exempted:
                # Key has not been used and has exceeded age threshold
                # NOT EXEMPT: Delete unused
                delete_access_key(
                    access_key_id, user_name, client_iam, client_ses, event
                )
                line = (
                    '<tr bgcolor= "#E6B0AA">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{ str(key_age)}</td>"
                    "<td>DELETED</td>"
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
                html_body += line

            # Process keys older than warning threshold
            if key_age < KEY_AGE_WARNING:
                continue

            if key_age >= KEY_AGE_DELETE and not exempted:
                # NOT EXEMPT: Delete
                delete_access_key(
                    access_key_id, user_name, client_iam, client_ses, event
                )
                line = (
                    '<tr bgcolor= "#E6B0AA">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{str(key_age)}</td>"
                    "<td>DELETED</td>"
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
            elif key_age >= KEY_AGE_INACTIVE and not exempted:
                # NOT EXEMPT: Disable
                disable_access_key(
                    access_key_id, user_name, client_iam, client_ses, event
                )
                line = (
                    '<tr bgcolor= "#F4D03F">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{str(key_age)}</td>"
                    f'<td>{key["Status"]}</td>'
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
            elif not exempted:
                # NOT EXEMPT: Report
                line = (
                    '<tr bgcolor= "#FFFFFF">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{str(key_age)}</td>"
                    f'<td>{key["Status"]}</td>'
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
            elif key_age >= KEY_AGE_DELETE and exempted and key["Status"] == "Inactive":
                # EXEMPT: Delete if Inactive
                delete_access_key(
                    access_key_id, user_name, client_iam, client_ses, event
                )
                line = (
                    '<tr bgcolor= "#E6B0AA">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{str(key_age)}</td>"
                    "<td>DELETED</td>"
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
            elif exempted:
                # EXEMPT: Report
                line = (
                    '<tr bgcolor= "#D7DBDD">'
                    f"<td>{user_name}</td>"
                    f'<td>{key["AccessKeyId"]}</td>'
                    f"<td>{str(key_age)}</td>"
                    f'<td>{key["Status"]}</td>'
                    f"<td>{str(last_used_date)}</td>"
                    "</tr>"
                )
            else:
                raise Exception(f"Unhandled case for Access Key {key['AccessKeyId']}")
            html_body += line

            # Log it
            log.info(
                "%s \t %s \t %s \t %s",
                user_name,
                key["AccessKeyId"],
                str(key_age),
                key["Status"],
            )
    if str(html_body) == "":
        html_body = "All Access Keys for this account are compliant."
    return html_body


def is_exempted(client_iam, user_name, event):
    """Determine if user is in an exempted group."""
    groups = client_iam.list_groups_for_user(UserName=user_name)
    for group in groups["Groups"]:
        if group["GroupName"] in event["exempt_groups"]:
            log.info("User is exempt via group membership in: %s", group["GroupName"])
            return True
    return False


###############################################################################
# Take action on Access Keys
###############################################################################


def delete_access_key(access_key_id, user_name, client, client_ses, event):
    """Delete Access Key."""
    log.info("Deleting AccessKeyId %s for user %s", access_key_id, user_name)

    if event["armed"]:
        client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        if event["email_user_enabled"]:
            email_targets = get_email_targets(client, user_name, event)
            email_html = get_email_html(
                user_name, access_key_id, KEY_AGE_DELETE, "deleted"
            )
            email_user(
                client_ses,
                f"IAM User Key Deleted for {user_name}",
                email_html,
                email_targets,
            )
        else:
            log.info("Email not enabled per environment variable setting")

    else:
        log.info("Not armed, no action taken")


def disable_access_key(access_key_id, user_name, client, client_ses, event):
    """Disable Access Key."""
    log.info("Disabling AccessKeyId %s for user %s", access_key_id, user_name)

    if event["armed"]:
        client.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )
        if event["email_user_enabled"]:
            email_targets = get_email_targets(client, user_name, event)
            email_html = get_email_html(
                user_name, access_key_id, KEY_AGE_INACTIVE, "disabled"
            )
            email_user(
                client_ses,
                f"IAM User Key Disabled for {user_name}",
                email_html,
                email_targets,
            )

        else:
            log.info("Email not enabled per environment variable setting")
    else:
        log.info("Not armed, no action taken")


def get_email_html(user_name, access_key_id, key_age, action):
    """Get the html for the email."""
    return (
        f"<html><h1>Expiring Access Key Report for {user_name} </h1>"
        f"<p>The following access key {access_key_id} is over {key_age} days old "
        f"and has been {action}.</p>"
        "<table>"
        "<tr><td><b>IAM User Name</b></td>"
        "<td><b>Access Key ID</b></td>"
        "<td><b>Key Age</b></td>"
        "<td><b>Key Status</b></td>"
        "<td><b>Last Used</b></td></tr></table></html>"
    )


def get_email_targets(client, user_name, event):
    """Get the users email if exists and admin email targets."""
    tags = client.list_user_tags(UserName=user_name)

    email = ""
    for tag in tags["Tags"]:
        if tag["Key"].lower() == EMAIL_TAG:
            email = tag["Value"]

    email_targets = []

    email_targets = _append_email_to_list(email_targets, ADMIN_EMAIL, "admin")

    for email_target in event["email_targets"]:
        email_targets = _append_email_to_list(email_targets, email_target, "target")

    email_targets = _append_email_to_list(email_targets, email, f"user ({user_name})")

    return email_targets


def email_user(client_ses, subject, html, email_targets):
    """Email user with the action taken on their key."""
    if len(email_targets) == 0:
        log.error("Email targets list is empty, no emails sent")
        return

    # Construct and Send Email
    response = client_ses.send_email(
        Destination={"ToAddresses": email_targets},
        Message={
            "Body": {
                "Html": {
                    "Charset": "UTF-8",
                    "Data": html,
                }
            },
            "Subject": {
                "Charset": "UTF-8",
                "Data": subject,
            },
        },
        Source=EMAIL_SOURCE,
    )
    log.info("Success. Message ID: %s", response["MessageId"])


def _append_email_to_list(email_list, email, email_type):
    if _is_valid_email_address(email):
        email_list.append(email)
    else:
        log.error(
            "Invalid %s email found - email: %s",
            email_type,
            email,
        )

    return email_list


def _is_valid_email_address(email):
    """Check to see if the email address is valid."""
    if not email:
        return False

    return re.fullmatch(email_regex, email)


def process_message(html_body, event):
    """Generate HTML and send report to email_targets list for tenant \
    accound and ADMIN_EMAIL via SES."""
    html_header = (
        "<html><h1>Expiring Access Key Report for "
        f'{event["account_number"]} - {event["account_name"]}</h1>'
        f"<p>The following access keys are over {KEY_AGE_WARNING} days old "
        f"and will soon be marked inactive ({KEY_AGE_INACTIVE} days) "
        f"and deleted ({KEY_AGE_DELETE} days).</p>"
        f"<p>Grayed out rows are exempt via membership in an IAM Group(s): "
        f'{", ".join(event["exempt_groups"])}</p>'
        "<table>"
        "<tr><td><b>IAM User Name</b></td>"
        "<td><b>Access Key ID</b></td>"
        "<td><b>Key Age</b></td>"
        "<td><b>Key Status</b></td>"
        "<td><b>Last Used</b></td></tr>"
    )

    html_footer = "</table></html>"
    html = html_header + html_body + html_footer
    log.info("%s", html)

    # Optionally write the report to S3
    if S3_ENABLED:
        client_s3 = SESSION.client("s3")
        s3_key = (
            event["account_number"]
            + "/access_key_audit_report_"
            + str(datetime.date.today())
            + ".html"
        )
        response = client_s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=html)
    else:
        log.info("S3 report not enabled per setting")

    # Optionally send report via SES Email
    if EMAIL_ADMIN_REPORT_ENABLED:
        # Establish SES Client
        client_ses = SESSION.client("ses")

        to_addresses = []
        for email_target in event["email_targets"]:
            to_addresses = _append_email_to_list(to_addresses, email_target, "target")
        to_addresses = _append_email_to_list(to_addresses, ADMIN_EMAIL, "admin")

        if len(to_addresses) == 0:
            log.error("Admin email list is empty, no emails sent")
            return

        # Construct and Send Email
        response = client_ses.send_email(
            Destination={"ToAddresses": to_addresses},
            Message={
                "Body": {
                    "Html": {
                        "Charset": "UTF-8",
                        "Data": html,
                    }
                },
                "Subject": {
                    "Charset": "UTF-8",
                    "Data": EMAIL_ADMIN_REPORT_SUBJECT,
                },
            },
            Source=EMAIL_SOURCE,
        )
        log.info("Success. Message ID: %s", response["MessageId"])
    else:
        log.info("Email not enabled per setting")


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
