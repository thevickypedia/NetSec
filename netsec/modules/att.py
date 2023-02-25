import json
import os
import socket
from collections.abc import Generator
from typing import Any, NoReturn, Optional, Union

import pandas
import requests
from pandas import DataFrame

from netsec.modules.helper import notify
from netsec.modules.settings import LOGGER, config

SOURCE = "http://{NETWORK_ID}.254/cgi-bin/devices.ha"


def get_ipaddress() -> str:
    """Get network id from the current IP address."""
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        socket_.connect(("8.8.8.8", 80))
        ip_address = socket_.getsockname()[0]
        network_id = '.'.join(ip_address.split('.')[0:3])
        socket_.close()
    except OSError as error:
        LOGGER.warning(error)
        network_id = "192.168.1"
    return network_id


SOURCE = SOURCE.format(NETWORK_ID=get_ipaddress())


class Device:
    """Convert dictionary into a device object.

    >>> Device

    """

    def __init__(self, dictionary: dict):
        """Set dictionary keys as attributes of Device object.

        Args:
            dictionary: Takes the input dictionary as an argument.
        """
        self.mac_address: Optional[str] = None
        self.ipv4_address: Optional[str] = None
        self.name: Optional[str] = None
        self.last_activity: Optional[str] = None
        self.status: Optional[str] = None
        self.allocation: Optional[str] = None
        self.connection_type: Optional[str] = None
        self.connection_speed: Optional[Union[float, Any]] = None
        self.mesh_client: Optional[str] = None
        for key in dictionary:
            setattr(self, key, dictionary[key])


def generate_dataframe() -> DataFrame:
    """Generate a dataframe using the devices information from router web page.

    Returns:
        DataFrame:
        Devices list as a data frame.
    """
    # pandas.set_option('display.max_rows', None)
    try:
        response = requests.get(url=SOURCE)
    except requests.RequestException as error:
        LOGGER.error(error)
        raise ConnectionError(error.args)
    else:
        if response.ok:
            html_source = response.text
            try:
                html_tables = pandas.read_html(html_source)
            except ImportError:
                raise ValueError("No tables found")
            return html_tables[0]
        else:
            LOGGER.error("[%s] - %s" % (response.status_code, response.text))


def format_key(key: str) -> str:
    """Format the key to match the Device object."""
    return key.lower().replace(' ', '_').replace('-', '_')


def get_attached_devices() -> Generator[Device]:
    """Get all devices connected to the router.

    Yields:
        Generator[Device]:
        Yields each device information as a Device object.
    """
    device_info = {}
    dataframe = generate_dataframe()
    if dataframe is None:
        return
    for value in dataframe.values:
        if str(value[0]) == "nan":
            yield Device(device_info)
            device_info = {}
        elif value[0] == "IPv4 Address / Name":
            key = value[0].split('/')
            val = value[1].split('/')
            device_info[format_key(key[0].strip())] = val[0].strip()
            device_info[format_key(key[1].strip())] = val[1].strip()
        else:
            device_info[format_key(value[0])] = value[1]


def create_snapshot() -> NoReturn:
    """Creates a snapshot.json which is used to determine the known and unknown devices."""
    devices = {}
    for device in get_attached_devices():
        if device.ipv4_address:
            devices[device.ipv4_address] = [str(device.name), str(device.connection_type), str(device.last_activity)]
    LOGGER.info('Number of devices connected: %d' % len(devices.keys()))
    with open(config.snapshot, 'w') as file:
        json.dump(devices, file, indent=2)


def run() -> NoReturn:
    """Trigger to initiate a Network Scan and block the devices that are not present in ``snapshot.json`` file."""
    if not os.path.isfile(config.snapshot):
        LOGGER.error("'%s' not found. Please pass `init=True` to generate snapshot and review it." % config.snapshot)
        raise FileNotFoundError(
            "'%s' is required" % config.snapshot
        )
    with open(config.snapshot) as file:
        device_list = json.load(file)
    stored_ips = list(device_list.keys())
    threats = []
    for device in get_attached_devices():
        if device.ipv4_address and device.ipv4_address not in stored_ips:
            # REMOTE = "http://{NETWORK_ID}.254/cgi-bin/remoteaccess.ha"
            LOGGER.warning('{name} [{ip}: {mac}] is connected to your network.'.format(name=device.name,
                                                                                       mac=device.mac_address,
                                                                                       ip=device.ipv4_address))
            threats.append(dict(Name=device.name, MAC=device.mac_address.upper(), IP=device.ipv4_address))
    if threats:
        notify(msg_dict=threats)
    else:
        LOGGER.info('NetSec has completed. No threats found on your network.')
