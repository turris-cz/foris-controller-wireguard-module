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

import pytest
from foris_controller_testtools.fixtures import (
    UCI_CONFIG_DIR_PATH,
    backend,
    file_root_init,
    infrastructure,
    init_script_result,
    network_restart_command,
    only_backends,
    uci_configs_init,
)


def test_key_management(infrastructure):
    filters = [
        ("wireguard", "server_generate_keys"),
        ("wireguard", "server_delete_keys"),
    ]

    # make sure that keys are deleted
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_delete_keys", "kind": "request"}
    )
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert res["data"]["ready"] is False, "Keys were deleted"

    # successful generation
    notifications = infrastructure.get_notifications(filters=filters)
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_generate_keys", "kind": "request"}
    )
    assert res["data"]["result"] is True, "generated"

    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1]["action"] == "server_generate_keys"

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert res["data"]["ready"] is True, "Keys were generated, it is ready"

    # second generation should fail
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_generate_keys", "kind": "request"}
    )
    assert res["data"]["result"] is False, "already generated"

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert res["data"]["ready"] is True, "already ready"

    # deleting keys
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_delete_keys", "kind": "request"}
    )
    assert res["data"]["result"] is True, "Keys were deleted"
    notifications = infrastructure.get_notifications(notifications, filters=filters)

    assert notifications[-1]["action"] == "server_delete_keys"

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert res["data"]["ready"] is False, "deleted"

    # already deleted
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_delete_keys", "kind": "request"}
    )
    assert res["data"]["result"] is False, "keys are not created"

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert res["data"]["ready"] is False, "already deleted"


def test_update_settings(infrastructure, network_restart_command):
    filters = [
        ("wireguard", "server_update_settings"),
    ]

    # generate server keys
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "server_generate_keys", "kind": "request"}
    )
    assert "errors" not in res

    notifications = infrastructure.get_notifications(filters=filters)
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "server_update_settings",
            "kind": "request",
            "data": {
                "enabled": True,
                "port": 11111,
                "networks": ["10.33.33.1/24", "fc00::1234/48"],
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        "module": "wireguard",
        "action": "server_update_settings",
        "kind": "notification",
        "data": {
            "enabled": True,
            "port": 11111,
            "networks": ["10.33.33.1/24", "fc00::1234/48"],
        },
    }

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    res["data"]["server"] == {
        "data": {
            "enabled": True,
            "port": 11111,
            "networks": ["10.33.33.1/24", "fc00::1234/48"],
        },
    }

    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "server_update_settings",
            "kind": "request",
            "data": {
                "enabled": False,
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        "module": "wireguard",
        "action": "server_update_settings",
        "kind": "notification",
        "data": {
            "enabled": False,
        },
    }

    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    res["data"]["server"] == {
        "data": {
            "enabled": False,
            "port": 11111,
            "networks": ["10.33.33.1/24", "fc00::1234/48"],
        },
    }


def test_client(infrastructure, network_restart_command):
    # to use get_settings we need to generate server keys
    infrastructure.process_message(
        {"module": "wireguard", "action": "server_generate_keys", "kind": "request"}
    )

    # and make sure that the server is configured (if uci is empty ip detection fails)
    infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "server_update_settings",
            "kind": "request",
            "data": {
                "enabled": True,
                "port": 11111,
                "networks": ["10.33.33.1/24", "fc00::1234/48"],
            },
        }
    )

    filters = [
        ("wireguard", "client_add"),
        ("wireguard", "client_del"),
        ("wireguard", "client_set"),
    ]

    # create clients
    notifications = infrastructure.get_notifications(filters=filters)
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_add",
            "kind": "request",
            "data": {
                "id": "test_client1",
                "allowed_ips": ["192.168.33.0/24", "fc00::5678/48"],
            },
        }
    )

    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        "module": "wireguard",
        "action": "client_add",
        "kind": "notification",
        "data": {
            "id": "test_client1",
            "allowed_ips": ["192.168.33.0/24", "fc00::5678/48"],
        },
    }

    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_add",
            "kind": "request",
            "data": {
                "id": "test_client1",
                "allowed_ips": ["192.168.33.0/24", "fc00::5678/48"],
            },
        }
    )
    assert res["data"]["result"] is False, "Already exists"

    # list client
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert "test_client1" in [e["id"] for e in res["data"]["clients"]]

    # disable client
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_set",
            "kind": "request",
            "data": {
                "id": "test_client1",
                "enabled": False,
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        "module": "wireguard",
        "action": "client_set",
        "kind": "notification",
        "data": {
            "id": "test_client1",
            "enabled": False,
        },
    }

    # test client export
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_export",
            "kind": "request",
            "data": {"id": "test_client1"},
        }
    )
    assert res["data"]["result"] is True
    assert "export" in res["data"]

    # test client export non-existing
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_export",
            "kind": "request",
            "data": {"id": "non_existing_client"},
        }
    )
    assert res["data"]["result"] is False
    assert "export" not in res["data"]

    # delete client
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_del",
            "kind": "request",
            "data": {"id": "test_client1"},
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1] == {
        "module": "wireguard",
        "action": "client_del",
        "kind": "notification",
        "data": {
            "id": "test_client1",
        },
    }

    # list client
    res = infrastructure.process_message(
        {"module": "wireguard", "action": "get_settings", "kind": "request"}
    )
    assert "test_client1" not in [e["id"] for e in res["data"]["clients"]]

    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "client_del",
            "kind": "request",
            "data": {"id": "test_client1"},
        }
    )
    assert res["data"]["result"] is False, "Already deleted"


def test_remote(infrastructure, network_restart_command):
    filters = [
        ("wireguard", "remote_import"),
        ("wireguard", "remote_set"),
        ("wireguard", "remote_del"),
    ]

    notifications = infrastructure.get_notifications(filters=filters)

    client = {
        "client": {
            "private_key": "OKMJPdIVdE5HIpRwQj71xDxE1tRuMThAXn3QP+QciW0=",
            "addresses": [
                "10.33.33.1/24",
                "fc00::1/48",
                "192.168.33.0/24",
                "fc00::5678/48",
            ],
        },
        "server": {
            "serial_number": "0000000000000011",
            "address": "1.2.3.4",
            "public_key": "Jlwf3Dg+gdSwv/FZOSSsUO+hENzhRwt+Rnk4L0DPQns=",
            "preshared_key": "OoY5J19gmprmarIa0/Lyn7KaiDX8iHWAiVEUi+iUgoQ=",
            "port": 11111,
            "networks": ["192.168.1.1/24", "10.33.33.1/24", "fc00::1234/48"],
            "dns": [],
        },
    }

    # test import
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "remote_import",
            "kind": "request",
            "data": {
                "id": "remote1",
                "export": client,
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1]["action"] == "remote_import"
    assert notifications[-1]["data"] == {
        "id": "remote1",
        "serial_number": "0000000000000011",
    }
    # TODO test get settings and check whether it is enabled

    # test set
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "remote_set",
            "kind": "request",
            "data": {
                "id": "remote1",
                "enabled": False,
                "networks": ["192.168.1.1/24", "10.33.33.1/24"],
                "server_address": "4.3.2.1",
                "server_port": 22222,
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1]["action"] == "remote_set"
    assert notifications[-1]["data"] == {
        "id": "remote1",
        "enabled": False,
        "networks": ["192.168.1.1/24", "10.33.33.1/24"],
        "server_address": "4.3.2.1",
        "server_port": 22222,
    }
    # TODO test get settings and check whether it is enabled

    # test delete
    res = infrastructure.process_message(
        {
            "module": "wireguard",
            "action": "remote_del",
            "kind": "request",
            "data": {
                "id": "remote1",
            },
        }
    )
    assert res["data"]["result"] is True
    notifications = infrastructure.get_notifications(notifications, filters=filters)
    assert notifications[-1]["action"] == "remote_del"
    assert notifications[-1]["data"] == {
        "id": "remote1",
    }
