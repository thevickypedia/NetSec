import copy
import json
import os
import time
from typing import NoReturn, Union

import yaml
from pynetgear import Device, Netgear

from netsec.modules.helper import notify
from netsec.modules.models import DeviceStatus
from netsec.modules.settings import LOGGER, config


class LocalIPScan:
    """Connector to scan devices in the same IP range using ``Netgear API``.

    >>> LocalIPScan

    """

    def __init__(self):
        """Gets local host devices connected to the same network range."""
        self.netgear = Netgear(password=config.router_pass)

    def _get_devices(self) -> Device:
        """Scans the Netgear router for connected devices and the devices' information.

        Returns:
            Device:
            Returns list of devices connected to the router and the connection information.
        """
        LOGGER.info('Getting devices connected to your network.')
        if devices := self.netgear.get_attached_devices():
            return devices
        else:
            text = "'router_pass' is invalid" if config.router_pass else "'router_pass' is required for netgear network"
            raise ValueError("\n\n" + text)

    def create_snapshot(self) -> NoReturn:
        """Creates a snapshot.json which is used to determine the known and unknown devices."""
        LOGGER.warning("Creating a snapshot will capture the current list of devices connected to your network at"
                       " this moment.")
        LOGGER.warning("This capture will be used to alert/block when new devices are connected. So, please review "
                       "the '%s' manually and remove the devices that aren't recognized." % config.snapshot)
        devices = {}
        for device in self._get_devices():
            if device.ip:  # Only look for currently connected devices
                devices[device.ip] = [device.name, device.type, device.allow_or_block]
        LOGGER.info('Number of devices connected: %d' % len(devices.keys()))
        with open(config.snapshot, 'w') as file:
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

    def _get_device_obj(self, device: str):
        """Identify device object using the device name as a string."""
        if isinstance(device, str):
            tmp = device
            LOGGER.info('Looking information on %s' % device)
            if device := self._get_device_by_name(name=device):
                return device
            else:
                LOGGER.error('Device: %s is not connected to your network.' % tmp)
        else:
            return device

    def allow(self, device: Union[str, Device]) -> Union[Device, None]:
        """Allows internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        if device := self._get_device_obj(device=device):
            LOGGER.info("Granting internet access to '%s'" % device.name)
            self.netgear.allow_block_device(mac_addr=device.mac, device_status=DeviceStatus.allow)
            return device

    def block(self, device: Union[str, Device]) -> Union[Device, None]:
        """Blocks internet access to a device.

        Args:
            device: Takes device name or Device object as an argument.

        Returns:
            Device:
            Returns the device object received from ``get_device_by_name()`` method.
        """
        device = self._get_device_obj(device=device)
        LOGGER.info("Blocking internet access to '%s'" % device.name)
        self.netgear.allow_block_device(mac_addr=device.mac, device_status=DeviceStatus.block)
        return device

    @staticmethod
    def _dump_blocked(device: Device) -> NoReturn:
        """Converts device object to a dictionary and dumps it into ``blocked.json`` file.

        Args:
            device: Takes Device object as an argument.
        """
        LOGGER.info("Details of '%s' has been stored in %s" % (device.name, config.blocked))
        with open(config.blocked, 'a') as file:
            # noinspection PyProtectedMember
            dictionary = {time.time(): device._asdict()}
            yaml.dump(dictionary, file, allow_unicode=True, default_flow_style=False, sort_keys=False)

    @staticmethod
    def _get_blocked():
        if os.path.isfile(config.blocked):
            with open(config.blocked) as file:
                try:
                    blocked_devices = yaml.load(stream=file, Loader=yaml.FullLoader) or {}
                except yaml.YAMLError as error:
                    LOGGER.error(error)
                else:
                    for epoch, device_info in blocked_devices.items():
                        yield device_info.get('mac')

    def always_allow(self, device: Device or str) -> NoReturn:
        """Allows internet access to a device.

        Saves the device name to ``snapshot.json`` to not block in the future.
        Removes the device name from ``blocked.json`` if an entry is present.

        Args:
            device: Takes device name or Device object as an argument
        """
        if isinstance(device, Device):
            device = device.name  # converts Device object to string
        if not (device := self.allow(device=device)):  # converts string to Device object
            return

        with open(config.snapshot, 'r+') as file:
            data = json.load(file)
            file.seek(0)
            if device.ip and device.ip in list(data.keys()):
                LOGGER.info("'%s' is a part of allow list." % device.name)
                data[device.ip][-1] = DeviceStatus.allow
                LOGGER.info("Setting status to Allow for '%s' in %s" % (device.name, config.snapshot))
            elif device.ip:
                data[device.ip] = [device.name, device.type, device.allow_or_block]
                LOGGER.info("Adding '%s' to %s" % (device.name, config.snapshot))
            json.dump(data, file, indent=2)
            file.truncate()

        if os.path.isfile(config.blocked):
            with open(config.blocked) as file:
                try:
                    blocked_devices = yaml.load(stream=file, Loader=yaml.FullLoader) or {}
                except yaml.YAMLError as error:
                    LOGGER.error(error)
                    return
            blocked_copy = copy.deepcopy(blocked_devices)
            for epoch, device_info in blocked_copy.items():  # convert to a list of dict
                if device_info.get('mac') == device.mac:
                    LOGGER.info("Removing '%s' from %s" % (device.name, config.blocked))
                    del blocked_devices[epoch]
            file.seek(0)
            file.truncate()
            if blocked_devices:
                yaml.dump(blocked_devices, file, indent=2)

    def run(self, block: bool = False) -> NoReturn:
        """Trigger to initiate a Network Scan and block the devices that are not present in ``snapshot.json`` file."""
        if not os.path.isfile(config.snapshot):
            LOGGER.error("'%s' not found. Please pass `init=True` to generate "
                         "snapshot and review it." % config.snapshot)
            raise FileNotFoundError(
                '%s is required' % config.snapshot
            )
        with open(config.snapshot) as file:
            device_list = json.load(file)
        stored_ips = list(device_list.keys())
        threat = []
        blocked = list(self._get_blocked())
        for device in self._get_devices():
            if device.ip and device.ip not in stored_ips:
                LOGGER.warning("{name} with MAC address {mac} and a signal strength of {signal}% has connected to your "
                               "network.".format(name=device.name, mac=device.mac, signal=device.signal))

                if device.allow_or_block == DeviceStatus.allow:
                    if block:
                        self.block(device=device)
                        if device.mac not in blocked:
                            self._dump_blocked(device=device)
                        else:
                            LOGGER.info("'%s' is a part of deny list." % device.name)
                    threat.append(dict(Name=device.name, IP=device.ip, MAC=device.mac))
                else:
                    LOGGER.info("'%s' does not have internet access." % device.name)

        if threat:
            notify(msg_dict=threat)
        else:
            LOGGER.info('NetSec has completed. No threats found on your network.')
