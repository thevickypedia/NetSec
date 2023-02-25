import logging
import os

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

    router_pass = os.environ.get('ROUTER_PASS') or os.environ.get('router_pass')
    gmail_user = os.environ.get('GMAIL_USER') or os.environ.get('gmail_user')
    gmail_pass = os.environ.get('GMAIL_PASS') or os.environ.get('gmail_pass')
    recipient = os.environ.get('RECIPIENT') or os.environ.get('recipient')
    docker = os.environ.get('DOCKER') or os.environ.get('docker')
    phone = os.environ.get('PHONE') or os.environ.get('phone')
    snapshot = os.path.join('fileio', 'snapshot.json')
    blocked = os.path.join('fileio', 'blocked.yaml')


config = Config()
