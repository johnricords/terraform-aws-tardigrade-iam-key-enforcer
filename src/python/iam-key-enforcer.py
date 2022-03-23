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
    ARMED: Set to "true" to take action on keys;
            "false" limits to reporting
    LOG_LEVEL: (optional): sets the level for function logging
            valid input: critical, error, warning, info (default), debug
    EMAIL_ENABLED: used to enable or disable the SES emailed report
    EMAIL_SOURCE: send from address for the email, authorized in SES
    EMAIL_SUBJECT: subject line for the email
    KEY_AGE_DELETE: age at which a key should be deleted (e.g. 120)
    KEY_AGE_INACTIVE: age at which a key should be inactive (e.g. 90)
    KEY_AGE_WARNING: age at which to warn (e.g. 75)
    KEY_USE_THRESHOLD: age at which unused keys should be deleted (e.g.30)
    S3_ENABLED: set to "true" and provide S3_BUCKET if the audit report
            should be written to S3
    S3_BUCKET: bucket name to write the audit report to if S3_ENABLED is
            set to "true"
 Event Variables:
    ACCOUNT_NAME: AWS Account (friendly) Name
    ACCOUNT_NUMBER: AWS Account Number
    EMAIL_USER_ENABLED: used to enable or disable the SES emailed report
    EMAIL_TARGET: default email address if event fails to pass a valid one
    EXEMPT_GROUPS: IAM Groups that are exempt from actions on access keys

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
import json

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
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "False").lower() == "true"
EMAIL_SUBJECT = os.environ.get("EMAIL_SUBJECT")
EMAIL_SOURCE = os.environ.get("EMAIL_SOURCE")
KEY_AGE_WARNING = int(os.environ.get("KEY_AGE_WARNING", 75))
KEY_AGE_INACTIVE = int(os.environ.get("KEY_AGE_INACTIVE", 90))
KEY_AGE_DELETE = int(os.environ.get("KEY_AGE_DELETE", 120))
KEY_USE_THRESHOLD = int(os.environ.get("KEY_USE_THRESHOLD", 30))
S3_ENABLED = os.environ.get("S3_ENABLED", "False").lower() == "true"
S3_BUCKET = os.environ.get("S3_BUCKET", None)

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
    ROLE_ARN = event["ROLE_ARN"]
    ROLE_SESSION_NAME = generate_lambda_session_name()  # see below for details

    # Assume the session
    ASSUMED_ROLE_SESSION = assume_role(
        SESSION, ROLE_ARN, RoleSessionName=ROLE_SESSION_NAME
    )

    # do stuff with the Lambda role using SESSION
    log.debug(SESSION.client("sts").get_caller_identity()["Arn"])

    # do stuff with the assumed role using ASSUMED_ROLE_SESSION
    log.debug(ASSUMED_ROLE_SESSION.client("sts").get_caller_identity()["Arn"])

    client_iam = ASSUMED_ROLE_SESSION.client("iam")
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

    log.info("Credential report generation throttled - exit")
    return exit


def get_credential_report(client_iam):
    """Process IAM Credential Report."""
    credential_report = client_iam.get_credential_report()
    credential_report_csv = io.StringIO(credential_report["Content"].decode("utf-8"))
    reader = csv.DictReader(credential_report_csv)
    return list(reader)


def process_users(
    client_iam, client_ses, event, report
):  # pylint: disable=too-many-branches
    """Process each user and key in the Credential Report."""
    # Initialize message content
    html_body = ""
    line = ""

    # Access the credential report and process it
    for row in report:
        # A row is a unique IAM user
        user_name = row["user"]
        log.debug("Processing user: %s", user_name)
        exemption = False
        if user_name != "<root_account>":

            # Test group exemption
            groups = client_iam.list_groups_for_user(UserName=user_name)
            for group in groups["Groups"]:
                if group["GroupName"] in event["EXEMPT_GROUPS"]:
                    exemption = True
                    log.info(
                        "User is exempt via group membership in: %s", group["GroupName"]
                    )
                    break

            # Process Access Keys for user
            access_keys = client_iam.list_access_keys(UserName=user_name)
            for key in access_keys["AccessKeyMetadata"]:
                key_age = object_age(key["CreateDate"])
                access_key_id = key["AccessKeyId"]

                # get time of last key use
                get_key = client_iam.get_access_key_last_used(AccessKeyId=access_key_id)

                # last_used_date value will not exist if key not used
                last_used_date = get_key["AccessKeyLastUsed"].get("LastUsedDate")

                if (
                    not last_used_date
                    and key_age >= KEY_USE_THRESHOLD
                    and not exemption
                ):
                    # Key has not been used and has exceeded age threshold
                    # NOT EXEMPT: Delete unused
                    delete_access_key(
                        access_key_id, user_name, client_iam, client_ses, event
                    )
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>DELETED</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            str(last_used_date),
                        )
                    )
                    html_body += line

                # Process keys older than warning threshold
                if key_age < KEY_AGE_WARNING:
                    continue

                if key_age >= KEY_AGE_DELETE and not exemption:
                    # NOT EXEMPT: Delete
                    delete_access_key(
                        access_key_id, user_name, client_iam, client_ses, event
                    )
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>DELETED</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            str(last_used_date),
                        )
                    )
                elif key_age >= KEY_AGE_INACTIVE and not exemption:
                    # NOT EXEMPT: Disable
                    disable_access_key(
                        access_key_id, user_name, client_iam, client_ses, event
                    )
                    line = (
                        '<tr bgcolor= "#F4D03F">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            key["Status"],
                            str(last_used_date),
                        )
                    )
                elif not exemption:
                    # NOT EXEMPT: Report
                    line = (
                        '<tr bgcolor= "#FFFFFF">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            key["Status"],
                            str(last_used_date),
                        )
                    )
                elif (
                    key_age >= KEY_AGE_DELETE
                    and exemption
                    and key["Status"] == "Inactive"
                ):
                    # EXEMPT: Delete if Inactive
                    delete_access_key(
                        access_key_id, user_name, client_iam, client_ses, event
                    )
                    line = (
                        '<tr bgcolor= "#E6B0AA">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>DELETED</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            str(last_used_date),
                        )
                    )
                elif exemption:
                    # EXEMPT: Report
                    line = (
                        '<tr bgcolor= "#D7DBDD">'
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "<td>{}</td>"
                        "</tr>".format(
                            user_name,
                            key["AccessKeyId"],
                            str(key_age),
                            key["Status"],
                            str(last_used_date),
                        )
                    )
                else:
                    raise Exception(
                        f"Unhandled case for Access Key {key['AccessKeyId']}"
                    )
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


###############################################################################
# Take action on Access Keys
###############################################################################


def delete_access_key(access_key_id, user_name, client, client_ses, event):
    """Delete Access Key."""
    log.info("Deleting AccessKeyId %s for user %s", access_key_id, user_name)

    if event["ARMED"]:
        client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
        email_user(access_key_id, user_name, client, client_ses, "deleted", event)
    else:
        log.info("Not armed, no action taken")


def disable_access_key(access_key_id, user_name, client, client_ses, event):
    """Disable Access Key."""
    log.info("Disabling AccessKeyId %s for user %s", access_key_id, user_name)

    if event["ARMED"]:
        client.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )
        email_user(access_key_id, user_name, client, client_ses, "disabled", event)
    else:
        log.info("Not armed, no action taken")


def email_user(access_key_id, user_name, client, client_ses, action, event):
    """Email user with the action taken on their key"""
    if event["EMAIL_USER_ENABLED"]:
        tags = client.list_user_tags(UserName=user_name)

        email = ""
        for tag in tags["Tags"]:
            if tag["Key"].toLower() == "email":
                email = tag["Value"]

        email_targets = [email["EMAIL_TARGET"], ADMIN_EMAIL]
        if is_valid_email(email):
            email_targets.append(email)
        if action == "disabled":
            subject = "IAM User Key Disabled for {}".format(user_name)
            key_age = KEY_AGE_INACTIVE
        else:
            subject = "IAM User Key Deleted for {}".format(user_name)
            key_age = KEY_AGE_DELETE

        html = (
            "<html><h1>Expiring Access Key Report for {} </h1>"
            "<p>The following access key {} is over {} days old "
            "and has been {}.</p>"
            "<table>"
            "<tr><td><b>IAM User Name</b></td>"
            "<td><b>Access Key ID</b></td>"
            "<td><b>Key Age</b></td>"
            "<td><b>Key Status</b></td>"
            "<td><b>Last Used</b></td></tr></table></html>".format(
                user_name,
                access_key_id,
                key_age,
                action,
            )
        )

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
    else:
        log.info("Email not enabled per environment variable setting")


def is_valid_email(email):
    if re.fullmatch(email_regex, email):
        return True
    return False


def process_message(html_body, event):
    """Generate HTML and send to SES."""
    html_header = (
        "<html><h1>Expiring Access Key Report for {} - {} </h1>"
        "<p>The following access keys are over {} days old "
        "and will soon be marked inactive ({} days) and deleted ({} days).</p>"
        "<p>Grayed out rows are exempt via membership in an IAM Group(s): {}</p>"
        "<table>"
        "<tr><td><b>IAM User Name</b></td>"
        "<td><b>Access Key ID</b></td>"
        "<td><b>Key Age</b></td>"
        "<td><b>Key Status</b></td>"
        "<td><b>Last Used</b></td></tr>".format(
            event["ACCOUNT_NUMBER"],
            event["ACCOUNT_NAME"],
            KEY_AGE_WARNING,
            KEY_AGE_INACTIVE,
            KEY_AGE_DELETE,
            ", ".join(event["EXEMPT_GROUPS"]),
        )
    )

    html_footer = "</table></html>"
    html = html_header + html_body + html_footer
    log.info("%s", html)

    # Optionally write the report to S3
    if S3_ENABLED:
        client_s3 = SESSION.client("s3")
        s3_key = (
            event["ACCOUNT_NUMBER"]
            + "/access_key_audit_report_"
            + str(datetime.date.today())
            + ".html"
        )
        response = client_s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=html)
    else:
        log.info("S3 report not enabled per setting")

    # Optionally send report via SES Email
    if EMAIL_ENABLED:
        # Establish SES Client
        client_ses = SESSION.client("ses")

        to_addresses = event["EMAIL_TARGET"]
        to_addresses.append(ADMIN_EMAIL)

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
                    "Data": EMAIL_SUBJECT,
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
