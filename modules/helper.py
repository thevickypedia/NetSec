import logging
import time
from datetime import datetime, timezone
from typing import NoReturn

import gmailconnector

from modules.settings import LOGGER, config


def custom_time(*args: logging.Formatter or time.time) -> time.struct_time:
    """Creates custom timezone for ``logging`` which gets used only when invoked by ``Docker``.

    This is used only when triggered within a ``docker container`` as it uses UTC timezone.

    Args:
        *args: Takes ``Formatter`` object and current epoch time as arguments passed by ``formatTime`` from ``logging``.

    Returns:
        struct_time:
        A struct_time object which is a tuple of:
        **current year, month, day, hour, minute, second, weekday, year day and dst** *(Daylight Saving Time)*
    """
    LOGGER.debug(args)
    local_timezone = datetime.now(tz=timezone.utc).astimezone().tzinfo
    return datetime.now().astimezone(tz=local_timezone).timetuple()


if config.docker:
    logging.Formatter.converter = custom_time


def notify(msg: str) -> NoReturn:
    """Send an email notification when there is a threat.

    Args:
        msg: Message that has to be sent.
    """
    if config.gmail_user and config.gmail_pass and config.recipient:
        emailer = gmailconnector.SendEmail(gmail_user=config.gmail_user,
                                           gmail_pass=config.gmail_pass)
        response = emailer.send_email(recipient=config.recipient,
                                      subject=f"Netscan Alert - {datetime.now().strftime('%C')}", body=msg)
        if response.ok:
            LOGGER.info("Firewall alert has been sent to '%s'" % config.phone)
        else:
            LOGGER.error("Failed to send a notification.\n%s" % response.body)
    else:
        LOGGER.info("Env variables not found to trigger notification.")
