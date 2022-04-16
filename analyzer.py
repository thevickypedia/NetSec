import importlib
import json
import logging
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import PurePath
from typing import AnyStr, NoReturn, Union

import yaml
from dotenv import load_dotenv
from gmailconnector.send_sms import Messenger
from pynetgear import Device, Netgear

importlib.reload(logging)
LOGGER = logging.getLogger(name=PurePath(__file__).stem)
log_formatter = logging.Formatter(
    fmt="%(asctime)s - [%(levelname)s] - %(name)s - %(funcName)s - Line: %(lineno)d - %(message)s",
    datefmt='%b-%d-%Y %H:%M:%S'
)
handler = logging.StreamHandler()
handler.setFormatter(fmt=log_formatter)
LOGGER.setLevel(level=logging.INFO)
LOGGER.addHandler(hdlr=handler)


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


def extract_str(input_: AnyStr) -> str:
    """Extracts strings from the received input.

    Args:
        input_: Takes a string as argument.

    Returns:
        str:
        A string after removing special characters.
    """
    return "".join([i for i in input_ if not i.isdigit() and i not in [",", ".", "?", "-", ";", "!", ":"]]).strip()


def device_name() -> str:
    """Gets the device name for MacOS and Windows."""
    if platform.system() == 'Darwin':
        system_kernel = subprocess.check_output("sysctl hw.model", shell=True).decode('utf-8').splitlines()
        return extract_str(system_kernel[0].split(':')[1])
    elif platform.system() == 'Windows':
        return subprocess.getoutput("WMIC CSPRODUCT GET VENDOR").replace('Vendor', '').strip()


def get_ssid() -> Union[str, None]:
    """Checks the current operating system and runs the appropriate command to get the SSID of the access point.

    Returns:
        str:
        SSID of the access point/router which is being accessed.
    """
    if platform.system() == 'Darwin':
        process = subprocess.Popen(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            stdout=subprocess.PIPE
        )
        out, err = process.communicate()
        if out.decode(encoding='UTF-8').strip() == "AirPort: Off":
            LOGGER.warning(f"{device_name()} WiFi is turned off.")
            return
        if error := process.returncode:
            LOGGER.error(f"Failed to fetch SSID with exit code: {error}\n{err}")
            return
        # noinspection PyTypeChecker
        return dict(map(str.strip, info.split(": ")) for info in out.decode("utf-8").splitlines()[:-1] if
                    len(info.split()) == 2).get("SSID")
    elif platform.system() == 'Windows':
        netsh = subprocess.check_output("netsh wlan show interfaces", shell=True)
        for info in netsh.decode('utf-8').split('\n')[:-1]:
            if 'SSID' in info:
                return info.strip('SSID').replace('SSID', '').replace(':', '').strip()


def send_sms(msg: str) -> NoReturn:
    """Sens an SMS notification when invoked by the ``run`` method.

    Args:
        msg: Message that has to be sent.
    """
    if os.environ.get('gmail_user') and os.environ.get('gmail_pass') and os.environ.get('phone'):
        messenger = Messenger(gmail_user=os.environ.get('gmail_user'), gmail_pass=os.environ.get('gmail_pass'),
                              phone=os.environ.get('phone'), subject="Cyber Alert", message=msg)
        response = messenger.send_sms()
        if response.ok:
            LOGGER.info(f"Firewall alert has been sent to {os.environ.get('phone')}")
        else:
            LOGGER.error(f"Failed to send a notification.\n{response.body}")


class LocalIPScan:
    """Connector to scan devices in the same IP range using ``Netgear API``.

    >>> LocalIPScan

    """

    def __init__(self, router_pass: str = None):
        """Gets local host devices connected to the same network range.

        Args:
            router_pass: Password to authenticate the API client.
        """
        env_file_path = '.env'
        load_dotenv(dotenv_path=env_file_path)
        if not router_pass:
            if not (router_pass := os.environ.get('router_pass')):
                raise ValueError(
                    'Router password is required.'
                )
        self.ssid = get_ssid() or 'your Network.'
        self.snapshot = 'snapshot.json'
        self.blocked = 'blocked.yaml'
        self.netgear = Netgear(password=router_pass)

    def _get_devices(self) -> Device:
        """Scans the Netgear router for connected devices and the devices' information.

        Returns:
            Device:
            Returns list of devices connected to the router and the connection information.
        """
        LOGGER.info(f'Getting devices connected to {self.ssid}')
        return self.netgear.get_attached_devices()

    def create_snapshot(self) -> NoReturn:
        """Creates a snapshot.json which is used to determine the known and unknown devices."""
        LOGGER.warning(f"Creating a snapshot will capture the current list of devices connected to {self.ssid} at"
                       " this moment.")
        LOGGER.warning("This capture will be used to alert/block when new devices are connected. So, "
                       f"please review the {self.snapshot} manually and remove the devices that aren't recognized.")
        devices = {}
        for device in self._get_devices():
            devices.update({str(device.ip): [str(device.name), str(device.type), str(device.allow_or_block)]})
        LOGGER.info(f'Number of devices connected: {len(list(devices.keys()))}')
        with open(self.snapshot, 'w') as file:
            json.dump(devices, file, indent=2)

    def _get_device_by_name(self, name: str) -> Device:
        """Calls the ``get_devices()`` method and checks if the given device is available in the list.

        Args:
            name: Takes device name as argument.

        Returns:
            Device:
            Returns device information as a Device object.
        """
        for device in self._get_devices():
            if device.name == name:
                return device

    def allow(self, device: Union[str, Device]) -> Union[Device, None]:
        """Allows internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        if isinstance(device, str):
            tmp = device
            LOGGER.info(f'Looking information on {device}')
            if not (device := self._get_device_by_name(name=device)):
                LOGGER.error(f'Device: {tmp} is not connected to {self.ssid}')
                return
        LOGGER.info(f'Granting internet access to {device.name}')
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Allow')
        return device

    def block(self, device: Union[str, Device]) -> Union[Device, None]:
        """Blocks internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        if isinstance(device, str):
            tmp = device
            LOGGER.info(f'Looking information on {device}')
            if not (device := self._get_device_by_name(name=device)):
                LOGGER.error(f'Device: {tmp} is not connected to {self.ssid}')
                return
        LOGGER.info(f'Blocking internet access to {device.name}')
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Block')
        return device

    def _dump_blocked(self, device: Device) -> NoReturn:
        """Converts device object to a dictionary and dumps it into ``blocked.json`` file.

        Args:
            device: Takes Device object as an argument.
        """
        LOGGER.info(f'Details of {device.name} has been stored in {self.blocked}')
        with open(self.blocked, 'a') as file:
            # noinspection PyProtectedMember
            dictionary = {time.time(): device._asdict()}
            yaml.dump(dictionary, file, allow_unicode=True, default_flow_style=False, sort_keys=False)

    def _stasher(self, device: Device) -> NoReturn:
        """Checks the ``blocked.json`` file for an existing record of the same device.

        If so, logs else calls ``dump_blocked()`` method.

        Args:
            device: Takes Device object as an argument.
        """
        blocked_devices = None
        blocked = []
        if os.path.isfile(self.blocked):
            with open(self.blocked) as file:
                if file.read().strip():
                    blocked_devices = yaml.load(stream=file, Loader=yaml.FullLoader)
            if blocked_devices:
                for epoch, device_info in blocked_devices.items():
                    blocked.append(device_info.get('mac'))

        if device.mac not in blocked:
            self._dump_blocked(device=device)
        else:
            LOGGER.info(f'{device.name} is a part of deny list.')

    def always_allow(self, device: Device or str) -> NoReturn:
        """Allows internet access to a device.

        Saves the device name to ``snapshot.json`` to not block in future.
        Removes the device name from ``blocked.json`` if an entry is present.

        Args:
            device: Takes device name or Device object as an argument
        """
        if isinstance(device, Device):
            device = device.name  # converts Device object to string
        if not (device := self.allow(device=device)):  # converts string to Device object
            return

        with open(self.snapshot, 'r+') as file:
            data = json.load(file)
            file.seek(0)
            if device.ip in list(data.keys()):
                LOGGER.info(f'{device.name} is a part of allow list.')
                data[device.ip][-1] = 'Allow'
                LOGGER.info(f'Setting status to Allow for {device.name} in {self.snapshot}')
            else:
                data.update({str(device.ip): [str(device.name), str(device.type), str(device.allow_or_block)]})
                LOGGER.info(f'Adding {device.name} to {self.snapshot}')

            json.dump(data, file, indent=2)
            file.truncate()

        if os.path.isfile(self.blocked):
            with open(self.blocked, 'r+') as file:
                if blocked_devices := yaml.load(stream=file, Loader=yaml.FullLoader):
                    for epoch, device_info in list(blocked_devices.items()):  # convert to a list of dict
                        if device_info.get('mac') == device.mac:
                            LOGGER.info(f'Removing {device.name} from {self.blocked}')
                            del blocked_devices[epoch]
                    file.seek(0)
                    file.truncate()
                    if blocked_devices:
                        yaml.dump(blocked_devices, file, indent=2)

    def run(self, block: bool = False) -> NoReturn:
        """Trigger to initiate a Network Scan and block the devices that are not present in ``snapshot.json`` file."""
        if not os.path.isfile(self.snapshot):
            LOGGER.error(f'{self.snapshot} not found. Please run `LocalIPScan().create_snapshot()` and review it.')
            raise FileNotFoundError(
                f'{self.snapshot} is required'
            )
        with open(self.snapshot) as file:
            device_list = json.load(file)
        threat = ''
        for device in self._get_devices():
            if device.ip not in list(device_list.keys()):
                LOGGER.warning(f'{device.name} with MAC address {device.mac} and a signal strength of {device.signal}% '
                               f'has connected to {self.ssid}')

                if device.allow_or_block == 'Allow':
                    if block:
                        self.block(device=device)
                        self._stasher(device=device)
                    threat += f'\nName: {device.name}\nIP: {device.ip}\nMAC: {device.mac}'
                else:
                    LOGGER.info(f'{device.name} does not have internet access.')

        if threat:
            send_sms(msg=threat)
        else:
            LOGGER.info(f'NetScan has completed. No threats found on {self.ssid}')


if __name__ == '__main__':
    if os.environ.get('DOCKER'):
        logging.Formatter.converter = custom_time
    LocalIPScan().run()
