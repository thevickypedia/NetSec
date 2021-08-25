from os import environ, path
from time import time

from dotenv import load_dotenv
from pynetgear import Netgear, Device
from yaml import dump, load, FullLoader


class LocalIPScan:
    def __init__(self, router_pass: str = None):
        env_file_path = '.env'
        load_dotenv(dotenv_path=env_file_path)
        if not router_pass:
            if not (router_pass := environ.get('router_pass')):
                raise ValueError(f'Router password is required.')
        self.snapshot = 'snapshot.yml'
        self.blocked = 'blocked.yml'
        self.netgear = Netgear(password=router_pass)

    def get_devices(self):
        return self.netgear.get_attached_devices()

    def create_snapshot(self):
        with open(self.snapshot, 'w') as file:
            for device in self.get_devices():
                file.write(f'{device.name}\n')

    def get_device_by_name(self, name: str):
        for device in self.get_devices():
            if device.name == name:
                return device

    def allow(self, device: str or Device):
        if isinstance(device, str):
            if not (device := self.get_device_by_name(name=device)):
                return
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Allow')
        return device

    def block(self, device: str or Device):
        if isinstance(device, str):
            if not (device := self.get_device_by_name(name=device)):
                return
        self.netgear.allow_block_device(mac_addr=device.mac, device_status='Block')
        return device

    def dump_blocked(self, device: Device):
        with open(self.blocked, 'a') as file:
            # noinspection PyProtectedMember
            dictionary = {time(): device._asdict()}
            dump(dictionary, file, allow_unicode=True, default_flow_style=False, sort_keys=False)

    def stasher(self, device: Device):
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
            self.dump_blocked(device=device)

    def run(self):
        if not path.isfile(self.snapshot):
            raise FileNotFoundError(f'{self.snapshot} is required ')
        with open(self.snapshot) as file:
            device_list = file.read().splitlines()
        for device in self.get_devices():
            if device.name not in device_list:
                if device.allow_or_block == 'Allow':
                    self.block(device=device)
                self.stasher(device=device)


if __name__ == '__main__':
    LocalIPScan().run()
