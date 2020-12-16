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

import ipaddress
import json
import logging
import os
import pathlib
import re
import typing

from foris_controller.app import app_info
from foris_controller_backends.cmdline import AsyncCommand, BaseCmdLine
from foris_controller_backends.files import BaseFile, inject_file_root, makedirs
from foris_controller_backends.maintain import MaintainCommands
from foris_controller_backends.services import OpenwrtServices
from foris_controller_backends.uci import (
    UciBackend,
    UciException,
    get_option_named,
    get_sections_by_type,
    parse_bool,
    store_bool,
)
from foris_controller_backends.wan import WanStatusCommands

logger = logging.getLogger(__name__)


IF_NAME_LEN = 10  # Interface name has to be less then 14 characters and is always prefixed with 'vpn'


def get_interface_name():
    return f"ws_{app_info['controller_id']}"


class WireguardAsync(AsyncCommand):
    def server_generate_keys(
        self, notify_function, exit_notify_function, reset_notify_function
    ):
        # make sure that directories exists
        makedirs(str(WireguardFile.SERVER_DIR))

        server_key = str(WireguardFile.server_key())
        server_pub = str(WireguardFile.server_pub())
        server_psk = str(WireguardFile.server_psk())

        def handler_exit(process_data):
            exit_notify_function(
                {
                    "task_id": process_data.id,
                    "status": "succeeded"
                    if process_data.get_retval() == 0
                    else "failed",
                }
            )

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function({"task_id": process_data.id, "status": status})

            return handler

        task_id = self.start_process(
            [
                "bash",
                "-c",
                f"/usr/bin/wg genkey | tee {inject_file_root(server_key)} | wg pubkey > {inject_file_root(server_pub)}"
                f"&& wg genpsk > {inject_file_root(server_psk)}",
            ],
            [
                (r"^TODO parse some output if there's any", gen_handler("TODO")),
            ],
            handler_exit,
            reset_notify_function,
        )

        return task_id

    def generate_client_keys(
        self, name, notify_function, exit_notify_function, reset_notify_function
    ):
        makedirs(str(WireguardFile.CLIENTS_DIR))

        client_key = str(WireguardFile.CLIENTS_DIR / f"{name}.key")
        client_pub = str(WireguardFile.CLIENTS_DIR / f"{name}.pub")

        def handler_exit(process_data):
            exit_notify_function(
                {
                    "task_id": process_data.id,
                    "name": name,
                    "status": "succeeded"
                    if process_data.get_retval() == 0
                    else "failed",
                }
            )

        def gen_handler(status):
            def handler(matched, process_data):
                notify_function(
                    {"task_id": process_data.id, "status": status, "name": name}
                )

            return handler

        task_id = self.start_process(
            [
                "bash",
                "-c",
                f"/usr/bin/wg genkey | tee {inject_file_root(client_key)} | wg pubkey > {inject_file_root(client_pub)}",
            ],
            [
                (r"^TODO parse some output if there's any", gen_handler("TODO")),
            ],
            handler_exit,
            reset_notify_function,
        )

        return task_id


class WireguardCmds(BaseCmdLine):
    def get_status(self):
        output, _ = self._run_command_and_check_retval(["/usr/bin/wg", "show"], 0)
        # TODO parse it
        raise NotImplementedError
        server_interface = get_interface_name()

        return {"server": {}, "clients": []}


class WireguardFile(BaseFile):
    ROOT_DIR = pathlib.Path("/etc/wireguard/")
    SERVER_DIR = ROOT_DIR / "server"
    CLIENTS_DIR = ROOT_DIR / "clients"

    @staticmethod
    def server_key() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.key"

    @staticmethod
    def server_pub() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.pub"

    @staticmethod
    def server_psk() -> pathlib.Path:
        return WireguardFile.SERVER_DIR / f"{app_info['controller_id']}.psk"

    def server_delete_keys(self):
        """ removes all keys """
        self.delete_file(str(WireguardFile.server_key()))
        self.delete_file(str(WireguardFile.server_pub()))
        self.delete_file(str(WireguardFile.server_psk()))
        self.delete_directory(WireguardFile.CLIENTS_DIR)


class WireguardUci:
    DEFAULTS = {
        "enabled": False,
        "network": "10.222.222.0",
        "network_netmask": "255.255.255.0",
        "routes": [],
        "port": 51820,
        "route_all": False,
        "use_dns": False,
    }

    def get_settings(self):
        raise NotImplementedError
        with UciBackend() as backend:
            data = backend.read("openvpn")
            foris_data = backend.read("foris")

        try:
            enabled = parse_bool(
                get_option_named(data, "openvpn", "server_turris", "enabled", "0")
            )
            network, network_netmask = get_option_named(
                data, "openvpn", "server_turris", "server", "10.111.111.0 255.255.255.0"
            ).split()
            push_options = get_option_named(
                data, "openvpn", "server_turris", "push", []
            )
            routes = [
                dict(
                    zip(("network", "netmask"), e.split()[1:])
                )  # `route <network> <netmask>`
                for e in push_options
                if e.startswith("route ")
            ]
            device = get_option_named(data, "openvpn", "server_turris", "dev", "")
            protocol = get_option_named(
                data, "openvpn", "server_turris", "proto", "udp"
            )
            ipv6 = "6" in protocol  # tcp6, tcp6-server, udp6
            protocol = "tcp" if protocol.startswith("tcp") else "udp"
            port = int(get_option_named(data, "openvpn", "server_turris", "port", "0"))
            use_dns = (
                True
                if [e for e in push_options if e.startswith("dhcp-option DNS")]
                else False
            )
            route_all = (
                True
                if [e for e in push_options if e == "redirect-gateway def1"]
                else False
            )
            server_hostname = get_option_named(
                foris_data, "foris", "openvpn_plugin", "server_address", ""
            )

        except UciException:
            return WireguardUci.DEFAULTS

        return {
            "enabled": enabled,
            "network": network,
            "network_netmask": network_netmask,
            "routes": routes,
            "device": device,
            "protocol": protocol,
            "port": port,
            "route_all": route_all,
            "use_dns": use_dns,
            "server_hostname": server_hostname,
            "ipv6": ipv6,
        }

    def server_update_settings(
        self,
        enabled,
        network=None,
        network_netmask=None,
        route_all=None,
        use_dns=None,
        protocol=None,
        ipv6=None,
    ):
        raise NotImplementedError
        with UciBackend() as backend:
            if enabled:
                network_data = backend.read("network")
                lan_ip = get_option_named(network_data, "network", "lan", "ipaddr")
                lan_netmask = get_option_named(
                    network_data, "network", "lan", "netmask"
                )

                backend.add_section("network", "interface", "vpn_turris")
                backend.set_option("network", "vpn_turris", "enabled", store_bool(True))
                backend.set_option("network", "vpn_turris", "ifname", "tun_turris")
                backend.set_option("network", "vpn_turris", "proto", "none")
                backend.set_option("network", "vpn_turris", "auto", store_bool(True))

                backend.add_section("firewall", "zone", "vpn_turris")
                backend.set_option(
                    "firewall", "vpn_turris", "enabled", store_bool(True)
                )
                backend.set_option("firewall", "vpn_turris", "name", "vpn_turris")
                backend.set_option("firewall", "vpn_turris", "input", "ACCEPT")
                backend.set_option("firewall", "vpn_turris", "forward", "REJECT")
                backend.set_option("firewall", "vpn_turris", "output", "ACCEPT")
                backend.set_option("firewall", "vpn_turris", "masq", store_bool(True))
                backend.replace_list(
                    "firewall", "vpn_turris", "network", ["vpn_turris"]
                )
                backend.add_section("firewall", "rule", "vpn_turris_rule")
                backend.set_option(
                    "firewall", "vpn_turris_rule", "enabled", store_bool(True)
                )
                backend.set_option(
                    "firewall", "vpn_turris_rule", "name", "vpn_turris_rule"
                )
                backend.set_option("firewall", "vpn_turris_rule", "target", "ACCEPT")
                backend.set_option("firewall", "vpn_turris_rule", "proto", protocol)
                backend.set_option("firewall", "vpn_turris_rule", "src", "wan")
                backend.set_option("firewall", "vpn_turris_rule", "dest_port", "1194")
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_lan_in"
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "enabled", store_bool(True)
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "src", "vpn_turris"
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_in", "dest", "lan"
                )
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_lan_out"
                )
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_lan_out",
                    "enabled",
                    store_bool(True),
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "src", "lan"
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_lan_out", "dest", "vpn_turris"
                )
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_wan_out"
                )
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_wan_out",
                    "enabled",
                    store_bool(True if route_all else False),
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_wan_out", "src", "vpn_turris"
                )
                backend.set_option(
                    "firewall", "vpn_turris_forward_wan_out", "dest", "wan"
                )

                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option(
                    "openvpn", "server_turris", "enabled", store_bool(True)
                )
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
                backend.set_option(
                    "network", "vpn_turris", "enabled", store_bool(False)
                )
                backend.add_section("firewall", "zone", "vpn_turris")
                backend.set_option(
                    "firewall", "vpn_turris", "enabled", store_bool(False)
                )
                backend.add_section("firewall", "rule", "vpn_turris_rule")
                backend.set_option(
                    "firewall", "vpn_turris_rule", "enabled", store_bool(False)
                )
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_lan_in"
                )
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_lan_in",
                    "enabled",
                    store_bool(False),
                )
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_lan_out"
                )
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_lan_out",
                    "enabled",
                    store_bool(False),
                )
                backend.add_section(
                    "firewall", "forwarding", "vpn_turris_forward_wan_out"
                )
                backend.set_option(
                    "firewall",
                    "vpn_turris_forward_wan_out",
                    "enabled",
                    store_bool(False),
                )
                backend.add_section("openvpn", "openvpn", "server_turris")
                backend.set_option(
                    "openvpn", "server_turris", "enabled", store_bool(False)
                )

        with OpenwrtServices() as services:
            MaintainCommands().restart_network()
            services.restart("openvpn", delay=3)

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
