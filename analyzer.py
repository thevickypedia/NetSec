import logging
from importlib import reload
from os import environ, path
from pathlib import PurePath
from platform import system
from subprocess import Popen, PIPE, check_output
from time import time
from typing import Union

from dotenv import load_dotenv
from pynetgear import Netgear, Device
from yaml import dump, load, FullLoader

reload(logging)
logger = logging.getLogger(PurePath(__file__).stem)
log_formatter = logging.Formatter(
    fmt="%(asctime)s - [%(levelname)s] - %(name)s - %(funcName)s - Line: %(lineno)d - %(message)s",
    datefmt='%b-%d-%Y %H:%M:%S'
)
handler = logging.StreamHandler()
handler.setFormatter(fmt=log_formatter)
logger.setLevel(level=logging.INFO)
logger.addHandler(hdlr=handler)


def ssid():
    """Checks the current operating system and runs the appropriate command to get the SSID of the access point.

    Returns:
        str:
        SSID of the access point/router which is being accessed.
    """
    if system() == 'Darwin':
        process = Popen(
            ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
            stdout=PIPE)
        out, err = process.communicate()
        if error := process.returncode:
            logger.error(f"Failed to fetch SSID with exit code: {error}\n{err}")
        # noinspection PyTypeChecker
        return dict(map(str.strip, info.split(': ')) for info in out.decode('utf-8').split('\n')[:-1]).get('SSID')
    elif system() == 'Windows':
        netsh = check_output("netsh wlan show interfaces", shell=True)
        for info in netsh.decode('utf-8').split('\n')[:-1]:
            if 'SSID' in info:
                return info.strip('SSID').replace('SSID', '').replace(':', '').strip()


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
            if not (router_pass := environ.get('router_pass')):
                raise ValueError(f'Router password is required.')
        self.ssid = ssid()
        self.snapshot = 'snapshot.yml'
        self.blocked = 'blocked.yml'
        self.netgear = Netgear(password=router_pass)

    def get_devices(self) -> Device:
        """Scans the Netgear router for connected devices and the devices' information.

        Returns:
            Device:
            Returns list of devices connected to the router and the connection information.
        """
        logger.info(f'Getting devices connected to {self.ssid}')
        return self.netgear.get_attached_devices()

    def create_snapshot(self) -> None:
        """Creates a snapshot.yml which is used to determine the known and unknown devices."""
        logger.warning(f"Creating a snapshot will capture the current list of devices connected to {self.ssid} at"
                       " this moment. This capture will be used to alert/block when new devices are connected. So, "
                       f"please review the {self.snapshot} manually and remove the devices that you don't recognize.")
        with open(self.snapshot, 'w') as file:
            for device in self.get_devices():
                file.write(f'{device.name}\n')

    def get_device_by_name(self, name: str) -> Device:
        """Calls the ``get_devices()`` method and checks if the given device is available in the list.

        Args:
            name: Takes device name as argument.

        Returns:
            Device:
            Returns device information as a Device object.
        """
        for device in self.get_devices():
            if device.name == name:
                return device

    def allow(self, device: str or Device) -> Union[Device, None]:
        """Allows internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        if isinstance(device, str):
            tmp = device
            logger.info(f'Looking information on {device}')
            if not (device := self.get_device_by_name(name=device)):
                logger.error(f'Device: {tmp} is not connected to {self.ssid}')
                return
        logger.info(f'Granting internet access to {device.name}')
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Allow')
        return device

    def block(self, device: str or Device) -> Union[Device, None]:
        """Blocks internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        if isinstance(device, str):
            tmp = device
            logger.info(f'Looking information on {device}')
            if not (device := self.get_device_by_name(name=device)):
                logger.error(f'Device: {tmp} is not connected to {self.ssid}')
                return
        logger.info(f'Blocking internet access to {device.name}')
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Block')
        return device

    def dump_blocked(self, device: Device) -> None:
        """Converts device object to a dictionary and dumps it into ``blocked.yml`` file.

        Args:
            device: Takes Device object as an argument.
        """
        logger.info(f'Details of {device.name} has been stored in {self.blocked}')
        with open(self.blocked, 'a') as file:
            # noinspection PyProtectedMember
            dictionary = {time(): device._asdict()}
            dump(dictionary, file, allow_unicode=True, default_flow_style=False, sort_keys=False)

    def stasher(self, device: Device) -> None:
        """Checks the ``blocked.yml`` file for an existing record of the same device.
        If so, logs else calls ``dump_blocked()`` method.

        Args:
            device: Takes Device object as an argument.
        """
        if path.isfile(self.blocked):
            with open(self.blocked) as file:
                blocked_devices = load(file, Loader=FullLoader)
            blocked = []
            if blocked_devices:
                for epoch, device_info in blocked_devices.items():
                    blocked.append(device_info.get('mac'))

            if device.mac not in blocked:
                self.dump_blocked(device=device)
            else:
                logger.info(f'{device.name} is a part of deny list.')
        else:
            self.dump_blocked(device=device)

    def run(self):
        """Trigger to initiate a Network Scan and block the devices that are not present in ``snapshot.yml`` file."""
        if not path.isfile(self.snapshot):
            logger.error(f'{self.snapshot} not found. Please run `LocalIPScan().create_snapshot()` and review it.')
            raise FileNotFoundError(f'{self.snapshot} is required ')
        with open(self.snapshot) as file:
            device_list = file.read().splitlines()
        for device in self.get_devices():
            if device.name not in device_list:
                logger.warning(f'{device.name} with MAC address {device.mac} and a signal strength of {device.signal}% '
                               f'has connected to {self.ssid}')

                if device.allow_or_block == 'Allow':
                    self.block(device=device)
                else:
                    logger.info(f'{device.name} does not have internet access.')

                self.stasher(device=device)


if __name__ == '__main__':
    LocalIPScan().run()
