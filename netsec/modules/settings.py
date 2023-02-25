import logging
import os
from typing import AnyStr

import dotenv

dotenv.load_dotenv(dotenv_path=".env")

if not os.path.isdir('fileio'):
    os.makedirs('fileio')

LOGGER = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(fmt=logging.Formatter(
    fmt="%(asctime)s - [%(levelname)s] - %(name)s - %(funcName)s - Line: %(lineno)d - %(message)s",
    datefmt='%b-%d-%Y %H:%M:%S'
))
LOGGER.setLevel(level=logging.DEBUG)
LOGGER.addHandler(hdlr=handler)


class Config:
    """Wrapper for all the environment variables."""

    router_pass: AnyStr = os.environ.get('ROUTER_PASS') or os.environ.get('router_pass')
    gmail_user: AnyStr = os.environ.get('GMAIL_USER') or os.environ.get('gmail_user')
    gmail_pass: AnyStr = os.environ.get('GMAIL_PASS') or os.environ.get('gmail_pass')
    recipient: AnyStr = os.environ.get('RECIPIENT') or os.environ.get('recipient')
    phone: AnyStr = os.environ.get('PHONE') or os.environ.get('phone')
    snapshot: os.PathLike = os.path.join('fileio', 'snapshot.json')
    blocked: os.PathLike = os.path.join('fileio', 'blocked.yaml')
    notification: os.PathLike = os.path.join('fileio', 'last_notify')


config = Config()
