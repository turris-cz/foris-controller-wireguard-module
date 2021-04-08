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

from foris_controller.handler_base import BaseOpenwrtHandler
from foris_controller.utils import logger_wrapper
from foris_controller_backends.wireguard import (
    WireguardCmds,
    WireguardFile,
    WireguardUci,
)

from .. import Handler

logger = logging.getLogger(__name__)


class OpenwrtWireguardHandler(Handler, BaseOpenwrtHandler):

    cmds = WireguardCmds()
    files = WireguardFile()
    uci = WireguardUci()

    @logger_wrapper(logger)
    def server_generate_keys(self) -> bool:
        if self.files.keys_ready():
            return False
        else:
            self.cmds.generate_server_keys()
            return True

    @logger_wrapper(logger)
    def server_delete_keys(self) -> bool:
        if self.files.keys_ready(any_ready=True):
            # if some keys are missing => clean it anyway
            self.files.server_delete_keys()
            return True
        else:
            return False

    @logger_wrapper(logger)
    def get_settings(self) -> dict:
        return self.uci.get_settings()

    @logger_wrapper(logger)
    def server_update_settings(self, enabled, networks=None, port=None) -> bool:
        return self.uci.server_update_settings(enabled, networks, port)

    @logger_wrapper(logger)
    def client_add(self, id, allowed_ips):
        return self.uci.add_client(id, allowed_ips)

    @logger_wrapper(logger)
    def client_del(self, id):
        return self.uci.del_client(id)

    @logger_wrapper(logger)
    def client_set(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def client_export(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def remote_import(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def remote_del(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def remote_set(self, *args, **kwargs):
        raise NotImplementedError()
