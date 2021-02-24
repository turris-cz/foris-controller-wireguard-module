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

import ipaddress
import json
import logging
import os
import pathlib
import re
import typing

from foris_controller.app import app_info
from foris_controller_backends.cmdline import BaseCmdLine
from foris_controller_backends.files import (
    BaseFile,
    inject_file_root,
    makedirs,
    path_exists,
)
from foris_controller_backends.maintain import MaintainCommands
from foris_controller_backends.services import OpenwrtServices
from foris_controller_backends.uci import (
    UciBackend,
    UciException,
    UciRecordNotFound,
    get_option_named,
    get_sections_by_type,
    parse_bool,
    store_bool,
)
from foris_controller_backends.wan import WanStatusCommands

logger = logging.getLogger(__name__)


def get_interface_name():
    return "wg_turris"
    # return f"wg_{app_info['controller_id']}"


class WireguardCmds(BaseCmdLine):
    def generate_server_keys(self):
        WireguardFile.makedirs()
        self._run_command_and_check_retval(
            [
                "/bin/sh",
                "-c",
                f'wg genkey | tee "{inject_file_root(str(WireguardFile.server_key()))}" | wg pubkey > "{inject_file_root(str(WireguardFile.server_pub()))}"',
            ],
            0,
        )
        self._run_command_and_check_retval(
            [
                "/bin/sh",
                "-c",
                f'wg genpsk > "{inject_file_root(str(WireguardFile.server_psk()))}"',
            ],
            0,
        )

    def get_status(self):
        output, _ = self._run_command_and_check_retval(["/usr/bin/wg", "show"], 0)
        # TODO parse it
        server_interface = get_interface_name()
        raise NotImplementedError
        return {"server": {}, "clients": []}


class WireguardFile(BaseFile):
    ROOT_DIR = pathlib.Path("/etc/wireguard/")
    SERVER_DIR = ROOT_DIR / "server"
    CLIENTS_DIR = ROOT_DIR / "clients"

    @staticmethod
    def keys_ready(any_ready=False):
        if any_ready:
            return (
                path_exists(str(WireguardFile.server_key()))
                or path_exists(str(WireguardFile.server_pub()))
                or path_exists(str(WireguardFile.server_psk()))
            )
        else:
            return (
                path_exists(str(WireguardFile.server_key()))
                and path_exists(str(WireguardFile.server_pub()))
                and path_exists(str(WireguardFile.server_psk()))
            )

    @staticmethod
    def makedirs():
        pathlib.Path(inject_file_root(str(WireguardFile.SERVER_DIR))).mkdir(
            parents=True, exist_ok=True
        )
        pathlib.Path(inject_file_root(str(WireguardFile.CLIENTS_DIR))).mkdir(
            parents=True, exist_ok=True
        )

    @staticmethod
    def server_key() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.key"

    @staticmethod
    def server_pub() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.pub"

    @staticmethod
    def server_psk() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.psk"

    @staticmethod
    def server_key_content() -> str:
        return BaseFile()._file_content(str(WireguardFile.server_key()))

    @staticmethod
    def server_pub_content() -> str:
        return BaseFile()._file_content(str(WireguardFile.server_pub()))

    @staticmethod
    def server_psk_content() -> str:
        return BaseFile()._file_content(str(WireguardFile.server_psk()))

    def server_delete_keys(self):
        """ removes all keys """
        self.delete_file(str(WireguardFile.server_key()))
        self.delete_file(str(WireguardFile.server_pub()))
        self.delete_file(str(WireguardFile.server_psk()))
        self.delete_directory(str(WireguardFile.CLIENTS_DIR))


class WireguardUci:
    DEFAULTS = {
        "enabled": False,
        "networks": ["10.211.211.0/24"],
        "port": 51820,
    }

    def get_settings(self) -> dict:
        if not WireguardFile.keys_ready():
            return {"ready": False}

        result = {
            "ready": True,
            "server": {},
            "clients": [],
            "remotes": [],
        }
        with UciBackend() as backend:
            data = backend.read("network")

        try:
            interface = get_interface_name()
            result["server"]["enabled"] = parse_bool(
                get_option_named(data, "network", interface, "enabled", "0")
            )
            result["server"]["networks"] = get_option_named(
                data,
                "network",
                interface,
                "addresses",
            )

        except (UciException, UciRecordNotFound):
            result["server"] = WireguardUci.DEFAULTS

        return result

    def server_update_settings(self, enabled, networks=None, port=None) -> bool:
        if not WireguardFile.keys_ready():
            return False

        with UciBackend() as backend:
            section = get_interface_name()
            if enabled:
                # networks and port has to be set
                backend.add_section("network", "interface", section)
                backend.set_option("network", section, "enabled", store_bool(True))
                backend.set_option("network", section, "proto", "wireguard")
                backend.set_option(
                    "network",
                    section,
                    "private_key",
                    WireguardFile.server_key_content().strip(),
                )
                backend.set_option("network", section, "enabled", port)
                backend.replace_list("network", "section", "network", ["vpn_turris"])

    def server_update_settings_old():
        if enabled:
            network_data = backend.read("network")
            lan_ip = get_option_named(network_data, "network", "lan", "ipaddr")
            lan_netmask = get_option_named(network_data, "network", "lan", "netmask")

            backend.add_section("network", "interface", "vpn_turris")
            backend.set_option("network", "vpn_turris", "enabled", store_bool(True))
            backend.set_option("network", "vpn_turris", "ifname", "tun_turris")
            backend.set_option("network", "vpn_turris", "proto", "none")
            backend.set_option("network", "vpn_turris", "auto", store_bool(True))

            backend.add_section("firewall", "zone", "vpn_turris")
            backend.set_option("firewall", "vpn_turris", "enabled", store_bool(True))
            backend.set_option("firewall", "vpn_turris", "name", "vpn_turris")
            backend.set_option("firewall", "vpn_turris", "input", "ACCEPT")
            backend.set_option("firewall", "vpn_turris", "forward", "REJECT")
            backend.set_option("firewall", "vpn_turris", "output", "ACCEPT")
            backend.set_option("firewall", "vpn_turris", "masq", store_bool(True))
            backend.replace_list("firewall", "vpn_turris", "network", ["vpn_turris"])
            backend.add_section("firewall", "rule", "vpn_turris_rule")
            backend.set_option(
                "firewall", "vpn_turris_rule", "enabled", store_bool(True)
            )
            backend.set_option("firewall", "vpn_turris_rule", "name", "vpn_turris_rule")
            backend.set_option("firewall", "vpn_turris_rule", "target", "ACCEPT")
            backend.set_option("firewall", "vpn_turris_rule", "proto", protocol)
            backend.set_option("firewall", "vpn_turris_rule", "src", "wan")
            backend.set_option("firewall", "vpn_turris_rule", "dest_port", "1194")
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_in")
            backend.set_option(
                "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(True)
            )
            backend.set_option(
                "firewall", "vpn_turris_forward_lan_in", "src", "vpn_turris"
            )
            backend.set_option("firewall", "vpn_turris_forward_lan_in", "dest", "lan")
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_out")
            backend.set_option(
                "firewall",
                "vpn_turris_forward_lan_out",
                "enabled",
                store_bool(True),
            )
            backend.set_option("firewall", "vpn_turris_forward_lan_out", "src", "lan")
            backend.set_option(
                "firewall", "vpn_turris_forward_lan_out", "dest", "vpn_turris"
            )
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_wan_out")
            backend.set_option(
                "firewall",
                "vpn_turris_forward_wan_out",
                "enabled",
                store_bool(True if route_all else False),
            )
            backend.set_option(
                "firewall", "vpn_turris_forward_wan_out", "src", "vpn_turris"
            )
            backend.set_option("firewall", "vpn_turris_forward_wan_out", "dest", "wan")

            backend.add_section("openvpn", "openvpn", "server_turris")
            backend.set_option("openvpn", "server_turris", "enabled", store_bool(True))
            backend.set_option("openvpn", "server_turris", "port", "1194")
            if ipv6:
                proto = "tcp6-server" if protocol == "tcp" else "udp6"
            else:
                proto = "tcp-server" if protocol == "tcp" else "udp"
            backend.set_option("openvpn", "server_turris", "proto", proto)
            backend.set_option("openvpn", "server_turris", "dev", "tun_turris")
            backend.set_option(
                "openvpn", "server_turris", "ca", "/etc/ssl/ca/openvpn/ca.crt"
            )
            backend.set_option(
                "openvpn",
                "server_turris",
                "crl_verify",
                "/etc/ssl/ca/openvpn/ca.crl",
            )
            backend.set_option(
                "openvpn", "server_turris", "cert", "/etc/ssl/ca/openvpn/01.crt"
            )
            backend.set_option(
                "openvpn", "server_turris", "key", "/etc/ssl/ca/openvpn/01.key"
            )
            backend.set_option(
                "openvpn", "server_turris", "dh", "/etc/ssl/ca/openvpn/dhparam.pem"
            )
            backend.set_option(
                "openvpn",
                "server_turris",
                "server",
                "%s %s" % (network, network_netmask),
            )
            backend.set_option(
                "openvpn", "server_turris", "ifconfig_pool_persist", "/tmp/ipp.txt"
            )
            backend.set_option(
                "openvpn", "server_turris", "duplicate_cn", store_bool(False)
            )
            backend.set_option("openvpn", "server_turris", "keepalive", "10 120")
            backend.set_option(
                "openvpn", "server_turris", "persist_key", store_bool(True)
            )
            backend.set_option(
                "openvpn", "server_turris", "persist_tun", store_bool(True)
            )
            backend.set_option(
                "openvpn", "server_turris", "status", "/tmp/openvpn-status.log"
            )
            backend.set_option("openvpn", "server_turris", "verb", "3")
            backend.set_option("openvpn", "server_turris", "mute", "20")
            push = [
                "route %s %s"
                % (
                    ipaddress.ip_network(
                        f"{lan_ip}/{lan_netmask}", False
                    ).network_address,
                    lan_netmask,
                )
            ]
            if route_all:
                push.append("redirect-gateway def1")
            if use_dns:
                # 10.111.111.0 -> 10.111.111.1
                # TODO this won't work when router ip is set to a different address
                push.append(
                    f"dhcp-option DNS {ipaddress.ip_network(network, False).network_address + 1}"
                )
            backend.replace_list("openvpn", "server_turris", "push", push)

        else:
            backend.add_section("network", "interface", "vpn_turris")
            backend.set_option("network", "vpn_turris", "enabled", store_bool(False))
            backend.add_section("firewall", "zone", "vpn_turris")
            backend.set_option("firewall", "vpn_turris", "enabled", store_bool(False))
            backend.add_section("firewall", "rule", "vpn_turris_rule")
            backend.set_option(
                "firewall", "vpn_turris_rule", "enabled", store_bool(False)
            )
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_in")
            backend.set_option(
                "firewall",
                "vpn_turris_forward_lan_in",
                "enabled",
                store_bool(False),
            )
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_lan_out")
            backend.set_option(
                "firewall",
                "vpn_turris_forward_lan_out",
                "enabled",
                store_bool(False),
            )
            backend.add_section("firewall", "forwarding", "vpn_turris_forward_wan_out")
            backend.set_option(
                "firewall",
                "vpn_turris_forward_wan_out",
                "enabled",
                store_bool(False),
            )
            backend.add_section("openvpn", "openvpn", "server_turris")
            backend.set_option("openvpn", "server_turris", "enabled", store_bool(False))

        MaintainCommands().restart_network()
        return True

    def update_server_hostname(self, server_hostname):
        with UciBackend() as backend:
            try:
                if server_hostname:
                    backend.add_section("turris-wg", "client")
                    backend.set_option(
                        "foris", "openvpn_plugin", "server_address", server_hostname
                    )
                else:
                    backend.del_option("foris", "openvpn_plugin", "server_address")
            except UciException:
                pass  # best effort (foris doesn't need to be installed...)

    def get_options_for_client(self):
        with UciBackend() as backend:
            data = backend.read("openvpn")

        dev = get_option_named(data, "openvpn", "server_turris", "dev", "tun_turris")
        proto = get_option_named(data, "openvpn", "server_turris", "proto", "udp")
        port = get_option_named(data, "openvpn", "server_turris", "port", "1194")
        ca_path = get_option_named(
            data, "openvpn", "server_turris", "ca", "/etc/ssl/ca/openvpn/ca.crt"
        )
        compress = get_option_named(data, "openvpn", "server_turris", "compress", "")

        # handle server in old configuration (can be removed once we migrate to openvpn 2.5)
        if not compress:
            old_lzo_present = parse_bool(
                get_option_named(data, "openvpn", "server_turris", "comp_lzo", "0")
            )
            compress = "lzo" if old_lzo_present else ""

        cipher = get_option_named(data, "openvpn", "server_turris", "cipher", "")
        tls_auth_path = get_option_named(
            data, "openvpn", "server_turris", "tls_auth", ""
        )
        return {
            "dev": dev,
            "proto": proto,
            "port": port,
            "ca_path": ca_path,
            "compress": compress,
            "cipher": cipher,
            "tls_auth_path": tls_auth_path,
        }

    def list(self) -> typing.List[dict]:

        with UciBackend() as backend:
            data = backend.read("openvpn")

        running_instances = OpenVpnUbus().openvpn_running_instances()
        logger.debug("Running openvpn instances %s", running_instances)

        return [
            {
                "id": e["name"],
                "enabled": parse_bool(e["data"].get("enabled", "0")),
                "running": e["name"] in running_instances,
            }
            for e in get_sections_by_type(data, "openvpn", "openvpn")
            if parse_bool(e["data"].get("_client_foris", "0"))
        ]

    def add(self, id: str, config: str) -> bool:

        with UciBackend() as backend:
            data = backend.read("openvpn")

            # try if it exists
            existing_ids = [
                e["name"] for e in get_sections_by_type(data, "openvpn", "openvpn")
            ]
            if id in existing_ids:
                return False

            # write config file
            dir_path = pathlib.Path("/etc/openvpn/foris")
            file_path = dir_path / f"{id}.conf"
            makedirs(str(dir_path), mask=0o0700)
            BaseFile()._store_to_file(str(file_path), config)

            # update uci
            backend.add_section("openvpn", "openvpn", id)
            backend.set_option("openvpn", id, "enabled", store_bool(True))
            backend.set_option("openvpn", id, "_client_foris", store_bool(True))
            backend.set_option("openvpn", id, "config", str(file_path))
            backend.set_option("openvpn", id, "dev", f"vpn{id[:IF_NAME_LEN]}")
            backend.add_to_list(
                "firewall", "turris_vpn_client", "device", [f"vpn{id[:IF_NAME_LEN]}"]
            )

        with OpenwrtServices() as services:
            MaintainCommands().restart_network()
            services.restart("openvpn", delay=3)

        return True

    def set(self, id: str, enabled: bool) -> bool:

        with UciBackend() as backend:
            data = backend.read("openvpn")

            # try if it exists
            existing_ids = [
                e["name"] for e in get_sections_by_type(data, "openvpn", "openvpn")
            ]
            if id not in existing_ids:
                return False

            # update uci
            backend.add_section("openvpn", "openvpn", id)
            backend.set_option("openvpn", id, "enabled", store_bool(enabled))

        with OpenwrtServices() as services:
            MaintainCommands().restart_network()
            services.restart("openvpn", delay=3)

        return True

    def delete(self, id: str) -> bool:

        with UciBackend() as backend:
            data = backend.read("openvpn")

            # try if it exists
            existing_ids = [
                e["name"] for e in get_sections_by_type(data, "openvpn", "openvpn")
            ]
            if id not in existing_ids:
                return False

            backend.del_section("openvpn", id)
            backend.del_from_list(
                "firewall", "turris_vpn_client", "device", [f"vpn{id[:IF_NAME_LEN]}"]
            )

            file_path = pathlib.Path("/etc/openvpn/foris") / f"{id}.conf"
            BaseFile().delete_file(str(file_path))

        with OpenwrtServices() as services:
            MaintainCommands().restart_network()
            services.restart("openvpn", delay=3)

        return True


class WireguardConfig(BaseFile):
    BASE_CERT_PATH = "/etc/ssl/ca/openvpn"

    def get_config(
        self, id, hostname, dev, proto, port, compress, cipher, tls_auth_path, ca_path
    ):
        ca = self._file_content(ca_path)
        cert = self._file_content(os.path.join(self.BASE_CERT_PATH, "%s.crt" % id))
        key = self._file_content(os.path.join(self.BASE_CERT_PATH, "%s.key" % id))

        if not hostname:
            # try to figure out wan ip
            try:
                addresses = WanStatusCommands().get_status()["ipv4"]
                hostname = addresses[0]
            except Exception as e:
                logger.warning("%r", e)
                hostname = "<server_address>"

        cipher_section = "cipher %s" % cipher if cipher else ""
        if tls_auth_path:
            tls_auth = self._file_content(tls_auth_path)
            tls_auth_section = "key-direction 1\n<tls-auth>\n%s\n</tls-auth>" % tls_auth
        else:
            tls_auth_section = ""
        compress = "compress %s" % compress if compress else ""

        # convert proto
        proto = proto[:3] + ("-client" if "server" in proto else "")

        return self.CONFIG_TEMPLATE % dict(
            dev=dev,
            proto=proto.replace("server", "client"),
            port=port,
            hostname=hostname,
            ca=ca,
            cert=cert,
            key=key,
            tls_auth_section=tls_auth_section,
            cipher_section=cipher_section,
            compress=compress,
        )
