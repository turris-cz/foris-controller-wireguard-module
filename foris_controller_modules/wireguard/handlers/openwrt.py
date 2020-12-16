#
# foris-controller-wireguard-module
# Copyright (C) 2020 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#

import logging
import typing

from foris_controller.handler_base import BaseOpenwrtHandler
from foris_controller.utils import logger_wrapper
from foris_controller_backends.wireguard import WireguardCmds, WireguardFiles, WireguardUci

from .. import Handler

logger = logging.getLogger(__name__)


class OpenwrtWireguardHandler(Handler, BaseOpenwrtHandler):

    asynchronous = WireguardAsync()
    cmds = WireguardCmds()
    files = WireguardFile()
    uci = WireguardUci()

    @logger_wrapper(logger)
    def list(self) -> typing.List[dict]:
        raise NotImplementedError

    @logger_wrapper(logger)
    def set(self, id: str, enabled: bool) -> bool:
        raise NotImplementedError

    @logger_wrapper(logger)
    def add(self, id: str, config: str) -> bool:
        raise NotImplementedError

    @logger_wrapper(logger)
    def delete(self, id: str) -> bool:
        raise NotImplementedError

    @logger_wrapper(logger)
    def generate_ca(self, notify, exit_notify, reset_notify):
        raise NotImplementedError

    @logger_wrapper(logger)
    def get_status(self):
        raise NotImplementedError

    @logger_wrapper(logger)
    def generate_client(self, name, notify, exit_notify, reset_notify):
        raise NotImplementedError

    @logger_wrapper(logger)
    def revoke(self, cert_id):
        raise NotImplementedError

    @logger_wrapper(logger)
    def delete_ca(self):
        raise NotImplementedError

    @logger_wrapper(logger)
    def get_settings(self):
        return self.uci.get_settings()

    @logger_wrapper(logger)
    def server_update_settings(
        self,
        enabled,
        network=None,
        network_netmask=None,
        route_all=None,
        use_dns=None,
        ipv6=None,
        protocol=None,
    ):
        raise NotImplementedError()
        return self.uci.server_update_settings(
            enabled, network, network_netmask, route_all, use_dns, protocol, ipv6
        )

    @logger_wrapper(logger)
    def get_client_config(self, id, hostname=None):
        raise NotImplementedError()
        filtered = [e for e in self.cmds.get_status()["clients"] if e["id"] == id]
        self.uci.update_server_hostname(hostname)  # update hostname in foris uci
        if not filtered:
            return {"status": "not_found"}
        if filtered[0]["status"] == "revoked":
            return {"status": "revoked"}

        options = self.uci.get_options_for_client()
        return {
            "status": "valid",
            "config": self.files.get_config(id=id, hostname=hostname, **options),
            "name": filtered[0]["name"],
        }
