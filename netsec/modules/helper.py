import os
import time
from datetime import datetime
from typing import Dict, List, NoReturn

import gmailconnector
import jinja2

from netsec.modules.settings import LOGGER, config


def _log_response(response: gmailconnector.Response) -> NoReturn:
    """Log response from gmail-connector."""
    if response.ok:
        LOGGER.info(response.body)
        return True
    LOGGER.error("Failed to send a notification.\n%s" % response.body)


def notify(msg_dict: List[Dict[str, str]]) -> NoReturn:
    """Send an email notification when there is a threat.

    Args:
        msg_dict: Dict message to be sent as template.
    """
    if not config.gmail_user and not config.gmail_pass and not (config.recipient or config.phone):
        LOGGER.info("Env variables not found to trigger notifications.")
        return
    if os.path.isfile(config.notification):
        with open(config.notification) as file:
            updated = file.read()
        if updated and time.time() - float(updated) < 3_600:
            LOGGER.info("Last notification was sent within an hour.")
            return
    sub = f"NetSec Alert - {datetime.now().strftime('%c')}"
    if config.recipient:
        with open(os.path.join(os.path.dirname(__file__), 'email_template.html')) as file:
            template = jinja2.Template(file.read())
        rendered = template.render(alerts=msg_dict)
        emailer = gmailconnector.SendEmail(gmail_user=config.gmail_user, gmail_pass=config.gmail_pass)
        response = emailer.send_email(recipient=config.recipient.email, sender="NetSec",
                                      subject=sub, html_body=rendered)
        if _log_response(response=response):
            with open(config.notification, 'w') as file:
                file.write(time.time().__str__())
    if config.phone:
        msg = ""
        for part in msg_dict:
            for key, value in part.items():
                msg += "%s: %s\n" % (key, value)
            msg += "\n"
        messenger = gmailconnector.SendSMS(gmail_user=config.gmail_user, gmail_pass=config.gmail_pass)
        response = messenger.send_sms(message=msg, subject=sub)
        if _log_response(response=response):
            with open(config.notification, 'w') as file:
                file.write(time.time().__str__())
