#
# foris-controller-openvpn_client-module
# Copyright (C) 2019 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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

import pytest
import pathlib
import textwrap

from .conftest import file_root, CMDLINE_SCRIPT_ROOT

from foris_controller_testtools.fixtures import (
    network_restart_command,
    init_script_result,
    uci_configs_init,
    only_backends,
    backend,
    infrastructure,
    notify_api,
    UCI_CONFIG_DIR_PATH,
    FILE_ROOT_PATH,
)

from foris_controller_testtools.utils import (
    sh_was_called,
    network_restart_was_called,
    get_uci_module,
    FileFaker,
)

from foris_controller.exceptions import UciRecordNotFound


@pytest.fixture(scope="function")
def ubus_service_list_cmd(request):

    # ubus call service list '{"name": "openvpn"}'
    content = """\
#!/bin/sh

cat << EOF
{
    "openvpn": {
        "instances": {
            "openwrt_first": {
                "running": true,
                "pid": 2827,
                "command": [
                    "\/usr\/sbin\/openvpn",
                    "--syslog",
                    "openvpn(openwrt_first)",
                    "--status",
                    "\/var\/run\/openvpn.openwrt_first.status",
                    "--cd",
                    "\/var\/etc",
                    "--config",
                    "openvpn-openwrt_first.conf"
                ],
                "term_timeout": 15,
                "respawn": {
                    "threshold": 3600,
                    "timeout": 5,
                    "retry": -1
                }
            },
            "openwrt_second": {
                "running": false,
                "pid": 2830,
                "command": [
                    "\/usr\/sbin\/openvpn",
                    "--syslog",
                    "openvpn(openwrt_second)",
                    "--status",
                    "\/var\/run\/openvpn.openwrt_second.status",
                    "--cd",
                    "\/var\/etc",
                    "--config",
                    "openvpn-openwrt_second.conf"
                ],
                "term_timeout": 15,
                "respawn": {
                    "threshold": 3600,
                    "timeout": 5,
                    "retry": -1
                }
            }
        }
    }
}
EOF
"""
    with FileFaker(CMDLINE_SCRIPT_ROOT, "/bin/ubus", True, textwrap.dedent(content)) as f:
        yield f


def add(infrastructure, id, config):
    return infrastructure.process_message(
        {
            "module": "openvpn_client",
            "action": "add",
            "kind": "request",
            "data": {"id": id, "config": config},
        }
    )


def set(infrastructure, id, enabled):
    return infrastructure.process_message(
        {
            "module": "openvpn_client",
            "action": "set",
            "kind": "request",
            "data": {"id": id, "enabled": enabled},
        }
    )


def delete(infrastructure, id):
    return infrastructure.process_message(
        {"module": "openvpn_client", "action": "del", "kind": "request", "data": {"id": id}}
    )


def list(infrastructure):
    return infrastructure.process_message(
        {"module": "openvpn_client", "action": "list", "kind": "request"}
    )["data"]["clients"]


def test_list(infrastructure, ubus_service_list_cmd):
    res = infrastructure.process_message(
        {"module": "openvpn_client", "action": "list", "kind": "request"}
    )
    assert "error" not in res
    assert "data" in res
    assert "clients" in res["data"]


def test_complext(
    uci_configs_init,
    init_script_result,
    infrastructure,
    network_restart_command,
    ubus_service_list_cmd,
):
    filters = [("openvpn_client", "add")]
    notifications = infrastructure.get_notifications(filters=filters)

    # add new
    res = add(infrastructure, "first", "1")
    assert "errors" not in res
    assert res["data"]["result"]
    assert {"id": "first", "enabled": True, "running": False} in list(infrastructure)

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": "openvpn_client",
        u"action": "add",
        u"kind": "notification",
        u"data": {"id": "first"},
    }

    # add existing
    res = add(infrastructure, "first", "2")
    assert "errors" not in res
    assert not res["data"]["result"]
    assert {"id": "first", "enabled": True, "running": False} in list(infrastructure)

    # set
    filters = [("openvpn_client", "set")]
    notifications = infrastructure.get_notifications(filters=filters)

    res = set(infrastructure, "first", False)
    assert "errors" not in res
    assert res["data"]["result"]
    assert {"id": "first", "enabled": False, "running": False} in list(infrastructure)

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": "openvpn_client",
        u"action": "set",
        u"kind": "notification",
        u"data": {"id": "first", "enabled": False},
    }

    res = set(infrastructure, "first", True)
    assert "errors" not in res
    assert res["data"]["result"]
    assert {"id": "first", "enabled": True, "running": False} in list(infrastructure)

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": "openvpn_client",
        u"action": "set",
        u"kind": "notification",
        u"data": {"id": "first", "enabled": True},
    }

    # set missing
    res = set(infrastructure, "second", False)
    assert "errors" not in res
    assert not res["data"]["result"]
    assert {"id": "first", "enabled": True, "running": False} in list(infrastructure)

    # del
    filters = [("openvpn_client", "del")]
    notifications = infrastructure.get_notifications(filters=filters)

    res = delete(infrastructure, "first")
    assert "errors" not in res
    assert res["data"]["result"]
    assert "first" not in {e["id"] for e in list(infrastructure)}

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        u"module": "openvpn_client",
        u"action": "del",
        u"kind": "notification",
        u"data": {"id": "first"},
    }

    # del missing (deleted)
    res = delete(infrastructure, "first")
    assert "errors" not in res
    assert not res["data"]["result"]
    assert "first" not in {e["id"] for e in list(infrastructure)}


@pytest.mark.only_backends(["openwrt"])
def test_complext_openwrt(
    uci_configs_init,
    init_script_result,
    infrastructure,
    network_restart_command,
    ubus_service_list_cmd,
):
    uci = get_uci_module(infrastructure.name)

    assert len(list(infrastructure)) == 0

    # add
    res = add(infrastructure, "openwrt_first", "config content")
    assert res["data"]["result"]

    assert network_restart_was_called([])
    assert sh_was_called(["/etc/init.d/openvpn", "restart"])

    with uci.UciBackend(UCI_CONFIG_DIR_PATH) as backend:
        data = backend.read()
    assert uci.parse_bool(uci.get_option_named(data, "openvpn", "openwrt_first", "enabled")) is True
    assert (
        uci.parse_bool(uci.get_option_named(data, "openvpn", "openwrt_first", "_client_foris"))
        is True
    )
    assert (
        uci.get_option_named(data, "openvpn", "openwrt_first", "config")
        == "/etc/openvpn/foris/openwrt_first.conf"
    )

    path = pathlib.Path(FILE_ROOT_PATH) / "etc/openvpn/foris/openwrt_first.conf"

    assert path.exists()
    assert path.read_text() == "config content"

    # test list
    clients = list(infrastructure)
    assert clients == [{"id": "openwrt_first", "enabled": True, "running": True}]

    res = set(infrastructure, "openwrt_first", False)
    assert res["data"]["result"]

    # set
    with uci.UciBackend(UCI_CONFIG_DIR_PATH) as backend:
        data = backend.read()

    assert network_restart_was_called([])
    assert sh_was_called(["/etc/init.d/openvpn", "restart"])

    assert (
        uci.parse_bool(uci.get_option_named(data, "openvpn", "openwrt_first", "enabled")) is False
    )

    # delete
    res = delete(infrastructure, "openwrt_first")
    assert res["data"]["result"]

    assert network_restart_was_called([])
    assert sh_was_called(["/etc/init.d/openvpn", "restart"])

    with uci.UciBackend(UCI_CONFIG_DIR_PATH) as backend:
        data = backend.read()

    with pytest.raises(UciRecordNotFound):
        uci.get_section(data, "openvpn", "openwrt_first")

    assert path.exists() is False


@pytest.mark.parametrize(
    "plain, sanitized",
    [
        ("my-sample-id", "my_sample_id"),
        ("-" * 50, "_" * 50),
        ("-", "_"),
        ("my.sample.id", "my_sample_id"),
        ("." * 50, "_" * 50),
        (".", "_"),
    ],
    ids=["dash", "max-dashes", "min-dashes", "dot", "max-dots", "min-dots"],
)
def test_add(
    uci_configs_init,
    init_script_result,
    infrastructure,
    network_restart_command,
    ubus_service_list_cmd,
    plain,
    sanitized,
):
    res = add(infrastructure, plain, "data")
    assert "errors" not in res
    assert {"id": sanitized, "enabled": True, "running": False} in list(infrastructure)
