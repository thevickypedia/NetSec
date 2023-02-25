from typing import NoReturn

from modules import att, models, netgear


def network_monitor(module: models.SupportedModules, init: bool = True) -> NoReturn:
    """Monitor devices connected to the network.

    Args:
        module: Module to scan. Currently, supports any network on a Netgear router or At&t networks.
        init: Takes a boolean value to create a snapshot file or actually monitor the network.
    """
    if module == models.SupportedModules.netgear:
        if init:
            netgear.LocalIPScan().create_snapshot()
        else:
            netgear.LocalIPScan().run()
    elif module == models.SupportedModules.att:
        if init:
            att.create_snapshot()
        else:
            att.run()
    else:
        raise ValueError(
            "\n\nnetwork argument should either be '%s' or '%s'" % (models.SupportedModules.att,
                                                                    models.SupportedModules.netgear)
        )


if __name__ == '__main__':
    network_monitor(module=models.SupportedModules.att, init=False)
