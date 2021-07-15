#
# foris-controller-wireguard-module
# Copyright (C) 2021 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

from foris_controller.handler_base import BaseMockHandler
from foris_controller.utils import logger_wrapper

from .. import Handler

logger = logging.getLogger(__name__)


class MockWireguardHandler(Handler, BaseMockHandler):
    clients: typing.Dict[str, dict] = []
    remotes: typing.List[dict] = []
    ready = False
    server = {
        "enabled": False,
        "port": 51820,
        "host": "1.2.3.4",
        "networks": ["10.211.211.0/24"],
    }

    @logger_wrapper(logger)
    def server_generate_keys(self) -> bool:
        if self.ready is False:
            self.ready = True
            return True
        else:
            return False

    @logger_wrapper(logger)
    def server_delete_keys(self) -> bool:
        if self.ready is False:
            return False
        else:
            self.ready = False
            return True

    @logger_wrapper(logger)
    def server_update_settings(self, enabled, networks=None, port=None) -> bool:
        self.server["enabled"] = enabled
        self.server["networks"] = networks or self.server["networks"]
        self.server["port"] = port or self.server["port"]
        return True

    @logger_wrapper(logger)
    def get_settings(self) -> dict:
        return (
            {
                "ready": True,
                "server": self.server,
                "clients": self.clients,
                "remotes": self.remotes,
            }
            if self.ready
            else {"ready": False}
        )

    @logger_wrapper(logger)
    def client_add(self, id, allowed_ips):
        if id in [e["id"] for e in self.clients]:
            return False

        self.clients.append(
            {
                "id": id,
                "enabled": True,
                "allowed_ips": allowed_ips,
            }
        )

        return True

    @logger_wrapper(logger)
    def client_del(self, id):
        if id not in [e["id"] for e in self.clients]:
            return False

        self.clients = [e for e in self.clients if e["id"] != id]

        return True

    @logger_wrapper(logger)
    def client_set(self, id, enabled):
        for client in self.clients:
            if client["id"] == id:
                client["enabled"] = enabled
                return True

        return False

    @logger_wrapper(logger)
    def client_export(self, id):
        for client in self.clients:
            if client["id"] == id:
                return {
                    "result": True,
                    "export": {
                        "server": {
                            "serial_number": "0011223344556677",
                            "preshared_key": "<preshared>",
                            "public_key": "<public>",
                            "address": "1.2.3.4",  # wan address
                            "port": self.server["port"],
                            "host": self.server["host"],
                            "networks": self.server["networks"] + ["192.168.24.1/24"],
                            "dns": [],
                        },
                        "client": {
                            "private_key": "<private>",
                            "addresses": client["allowed_ips"],
                        },
                    },
                }

        return {"result": False}

    @logger_wrapper(logger)
    def remote_import(self, server, client):
        if any(
            e["server"]["serial_number"] == server["serial_number"]
            for e in self.remotes
        ):
            return False

        self.remotes.push(
            {
                "server": server,
                "client": client,
            }
        )
        return True

    @logger_wrapper(logger)
    def remote_del(self, id, serial_number):
        new_remotes = [
            e
            for e in self.remotes
            if e["id"] == id and e["serial_number"] == serial_number
        ]
        if len(new_remotes) == self.self.remotes:
            return False

        self.remotes = new_remotes

        return True

    @logger_wrapper(logger)
    def remote_set(self, *args, **kwargs):
        raise NotImplementedError()
