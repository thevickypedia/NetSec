from typing import NoReturn

import gmailconnector

from netsec.modules import att, models, netgear, settings


def network_monitor(module: models.SupportedModules, init: bool = True, block: bool = False) -> NoReturn:
    """Monitor devices connected to the network.

    Args:
        module: Module to scan. Currently, supports any network on a Netgear router or At&t networks.
        init: Takes a boolean value to create a snapshot file or actually monitor the network.
        block: Takes a boolean value whether to block the intrusive device.
    """
    if settings.config.recipient:
        settings.config.recipient = gmailconnector.EmailAddress(address=settings.config.recipient)
    if module == models.SupportedModules.netgear:
        if not settings.config.router_pass:
            raise ValueError(
                "\n\n'router_pass' is required for NetGear routers"
            )
        if init:
            netgear.LocalIPScan().create_snapshot()
        else:
            netgear.LocalIPScan().run(block=block)
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
