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

from foris_controller.handler_base import wrap_required_functions
from foris_controller.module_base import BaseModule


class WireguardModule(BaseModule):
    logger = logging.getLogger(__name__)

    def action_server_generate_keys(self, data):
        res = self.handler.server_generate_keys()
        if res:
            self.notify("server_generate_keys")

        return {"result": res}

    def action_server_delete_keys(self, data):
        res = self.handler.server_delete_keys()
        if res:
            self.notify("server_delete_keys")
        return {"result": res}

    def action_server_update_settings(self, data):
        res = self.handler.server_update_settings(**data)
        if res:
            self.notify("server_update_settings", data)

        return {"result": res}

    def action_client_add(self, data):
        def notify(msg):
            self.notify("client_add", msg)

        # notify and exit notify are the same
        async_id = self.handler.client_add(
            data["name"], notify, notify, self.reset_notify
        )

        return {"task_id": async_id}

    def action_client_del(self, data):
        res = self.handler.client_del(data["id"])
        if res:
            self.notify("client_del", {"id": data["id"]})
        return {"result": res}

    def action_client_set(self, data):
        res = self.handler.client_set(**data)
        if res:
            self.notify("client_set", data)
        return {"result": res}

    def action_client_export(self, data):
        return self.handler.get_client_export(**data)

    def action_remote_import(self, data):
        res = self.handler.remote_import(**data)
        if res:
            self.notify("remote_import", {"id": data["id"]})
        return {"result": res}

    def action_remote_del(self, data):
        res = self.handler.remote_del(data["id"])
        if res:
            self.notify("remote_del", {"id": data["id"]})
        return {"result": res}

    def action_remote_set(self, data):
        res = self.handler.remote_set(**data)
        if res:
            self.notify("remote_set", data)
        return {"result": res}

    def action_get_settings(self, data):
        return self.handler.get_settings()


@wrap_required_functions(
    [
        "server_generate_keys",
        "server_delete_keys",
        "server_update_settings",
        "get_settings",
        "client_add",
        "client_del",
        "client_set",
        "client_export",
        "remote_import",
        "remote_del",
        "remote_set",
    ]
)
class Handler:
    pass
