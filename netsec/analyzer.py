from typing import NoReturn

from gmailconnector.validator import address as email_address

from netsec.modules import att, models, netgear, settings


def network_monitor(module: models.SupportedModules, init: bool = True, block: bool = False) -> NoReturn:
    """Monitor devices connected to the network.

    Args:
        module: Module to scan. Currently, supports any network on a Netgear router or At&t networks.
        init: Takes a boolean value to create a snapshot file or actually monitor the network.
        block: Takes a boolean value whether to block the intrusive device.
    """
    if settings.config.recipient:
        email_address.logger = settings.LOGGER
        settings.config.recipient = email_address.ValidateAddress(address=settings.config.recipient)  # noqa
    if module == models.SupportedModules.netgear:
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
