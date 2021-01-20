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
    clients: typing.List[dict] = []
    remotes: typing.List[dict] = []
    settings = {
        "ready": False,
    }

    @logger_wrapper(logger)
    def server_generate_keys(self):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def server_delete_keys(self):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def server_update_settings(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def get_settings(self):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def client_add(self, *args, **kwargs):
        raise NotImplementedError()

    @logger_wrapper(logger)
    def client_del(self, *args, **kwargs):
        raise NotImplementedError()

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
