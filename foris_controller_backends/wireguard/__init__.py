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
import itertools
import json
import logging
import os
import pathlib
import re
import typing

from foris_controller.app import app_info
from foris_controller_backends.about import CryptoWrapperCmds
from foris_controller_backends.cmdline import BaseCmdLine
from foris_controller_backends.files import (
    BaseFile,
    inject_file_root,
    makedirs,
    path_exists,
)
from foris_controller_backends.lan import LanUci
from foris_controller_backends.maintain import MaintainCommands
from foris_controller_backends.services import OpenwrtServices
from foris_controller_backends.uci import (
    UciBackend,
    UciException,
    UciRecordNotFound,
    get_option_named,
    get_sections_by_type,
    parse_bool,
    section_exists,
    store_bool,
)
from foris_controller_backends.wan import WanStatusCommands

logger = logging.getLogger(__name__)


def get_interface_name():
    return f"wg_{app_info['controller_id']}"


def get_zone_name():
    return get_interface_name()


def get_wg_client_type():
    return f"wireguard_{get_interface_name()}"


class WireguardCmds(BaseCmdLine):
    def generate_client_keys(self, client_id):
        self._generate_keys(
            WireguardFile.client_key(client_id),
            WireguardFile.client_pub(client_id),
            WireguardFile.client_psk(client_id),
        )

    def generate_server_keys(self):
        self._generate_keys(
            WireguardFile.server_key(),
            WireguardFile.server_pub(),
            WireguardFile.server_psk(),
        )

    def _generate_keys(
        self, key_path: pathlib.Path, pub_path: pathlib.Path, psk_path: pathlib.Path
    ):
        WireguardFile.makedirs()
        self._run_command_and_check_retval(
            [
                "/bin/sh",
                "-c",
                f'wg genkey | tee "{inject_file_root(str(key_path))}" | wg pubkey > "{inject_file_root(str(pub_path))}"',
            ],
            0,
        )
        self._run_command_and_check_retval(
            [
                "/bin/sh",
                "-c",
                f'wg genpsk > "{inject_file_root(str(psk_path))}"',
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
    REMOTES_DIR = ROOT_DIR / "remotes"

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

    @staticmethod
    def client_key(client_id: str) -> pathlib.Path:
        return WireguardFile.CLIENTS_DIR / f"{client_id}.key"

    @staticmethod
    def client_pub(client_id: str) -> pathlib.Path:
        return WireguardFile.CLIENTS_DIR / f"{client_id}.pub"

    @staticmethod
    def client_psk(client_id: str) -> pathlib.Path:
        return WireguardFile.CLIENTS_DIR / f"{client_id}.psk"

    @staticmethod
    def client_key_content(client_id: str) -> str:
        return BaseFile()._file_content(str(WireguardFile.client_key(client_id)))

    @staticmethod
    def client_pub_content(client_id: str) -> str:
        return BaseFile()._file_content(str(WireguardFile.client_pub(client_id)))

    @staticmethod
    def client_psk_content(client_id: str) -> str:
        return BaseFile()._file_content(str(WireguardFile.client_psk(client_id)))

    def server_delete_keys(self):
        """removes all server keys"""
        self.delete_file(str(WireguardFile.server_key()))
        self.delete_file(str(WireguardFile.server_pub()))
        self.delete_file(str(WireguardFile.server_psk()))

    def delete_client_keys(self, client_id: str):
        """remove keys of a client"""
        self.delete_file(str(WireguardFile.client_key(client_id)))
        self.delete_file(str(WireguardFile.client_pub(client_id)))
        self.delete_file(str(WireguardFile.client_psk(client_id)))


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
            result["server"]["enabled"] = not parse_bool(
                get_option_named(data, "network", interface, "disabled", "0")
            )
            result["server"]["networks"] = get_option_named(
                data,
                "network",
                interface,
                "addresses",
            )
            result["server"]["port"] = int(
                get_option_named(data, "network", interface, "listen_port")
            )

            # read clients
            for client_section in get_sections_by_type(
                data, "network", get_wg_client_type()
            ):
                client = {
                    "id": client_section["name"][len("wg_client_") - 1 :],
                    "allowed_ips": client_section["data"].get("allowed_ips", []),
                    "enabled": not parse_bool(
                        client_section["data"].get("disabled", "0")
                    ),
                }
                result["clients"].append(client)

        except (UciException, UciRecordNotFound):
            result["server"] = WireguardUci.DEFAULTS

        return result

    def server_update_settings(self, enabled, networks=None, port=None) -> bool:
        # TODO need to decide what to do when IP address range in wg network changes
        # how to reflect this configuration in peer section + clients would use different addresses
        # perhaps if there are clients addresses in LAN network should be readonly should be read only
        if not WireguardFile.keys_ready():
            return False

        with UciBackend() as backend:
            interface = get_interface_name()
            zone = get_zone_name()
            rule = f"{zone}_rule"
            f_lan_in = f"{zone}_f_lan_in"
            f_lan_out = f"{zone}_f_lan_out"
            f_wan_out = f"{zone}_f_wan_out"

            # configure interface
            backend.add_section("network", "interface", interface)
            backend.set_option(
                "network", interface, "disabled", store_bool(not enabled)
            )
            backend.set_option("network", interface, "proto", "wireguard")
            backend.set_option(
                "network",
                interface,
                "private_key",
                WireguardFile.server_key_content().strip(),
            )
            if enabled:
                backend.set_option("network", interface, "listen_port", port)
                backend.replace_list("network", interface, "addresses", networks)

            # configure firewall

            # add wg zone
            backend.add_section("firewall", "zone", zone)
            backend.set_option("firewall", zone, "enabled", store_bool(enabled))
            backend.set_option("firewall", zone, "name", zone)
            backend.set_option("firewall", zone, "input", "ACCEPT")
            backend.set_option("firewall", zone, "forward", "REJECT")
            backend.set_option("firewall", zone, "output", "ACCEPT")
            backend.set_option("firewall", zone, "masq", store_bool(True))
            backend.replace_list("firewall", zone, "network", [interface])

            # add forwarding
            backend.add_section("firewall", "forwarding", f_lan_in)
            backend.set_option("firewall", f_lan_in, "enabled", store_bool(enabled))
            backend.set_option("firewall", f_lan_in, "src", "lan")
            backend.set_option("firewall", f_lan_in, "dest", interface)

            backend.add_section("firewall", "forwarding", f_lan_out)
            backend.set_option("firewall", f_lan_out, "enabled", store_bool(enabled))
            backend.set_option("firewall", f_lan_out, "src", interface)
            backend.set_option("firewall", f_lan_out, "dest", "lan")

            backend.add_section("firewall", "forwarding", f_wan_out)
            backend.set_option("firewall", f_wan_out, "enabled", store_bool(enabled))
            backend.set_option("firewall", f_wan_out, "src", interface)
            backend.set_option("firewall", f_wan_out, "dest", "wan")

            # add wan rule
            backend.add_section("firewall", "rule", rule)
            backend.set_option("firewall", rule, "enabled", store_bool(enabled))
            backend.set_option("firewall", rule, "name", zone)
            backend.set_option("firewall", rule, "target", "ACCEPT")
            backend.set_option("firewall", rule, "proto", "udp")
            backend.set_option("firewall", rule, "src", "wan")
            backend.set_option("firewall", rule, "dest_port", port)

        MaintainCommands().restart_network()
        return True

    def add_wireguard_remote(self):
        # TODO create interface similary to when the server is starting
        # add private key obtained from the server
        pass

    @staticmethod
    def _get_lan_addresses(network_config) -> ipaddress.IPv4Interface:
        address, netmask, *_ = LanUci._get_network_combo(network_config)
        return ipaddress.ip_interface(f"{address}/{netmask}")

    @staticmethod
    def _get_wan_address():
        return WanStatusCommands().get_status()["ipv4"][0]

    @staticmethod
    def _get_wg_network_client_ips(
        data, cli_name: str, section: str
    ) -> typing.List[str]:
        client_networks = get_option_named(data, "network", cli_name, "allowed_ips", [])
        client_networks = [ipaddress.ip_interface(e) for e in client_networks]
        network_addresses = get_option_named(
            data,
            "network",
            get_interface_name(),
            "addresses",
        )
        network_addresses = [ipaddress.ip_interface(e) for e in network_addresses]
        existing_ips = itertools.chain(
            *[
                e["data"].get("allowed_ips", [])
                for e in get_sections_by_type(data, "network", section)
            ]
        )
        existing_ips = [ipaddress.ip_interface(e).ip for e in existing_ips]

        res = []
        # test whether client has an IP assigned within wg network
        for network in network_addresses:
            # already present
            present = False
            for e in client_networks:
                if e.ip in network.network:
                    res.append(str(e))
                    present = True
                    break

            if present:
                continue

            # derive new ip > itetrate through unusend
            for ip in itertools.islice(
                network.network, 1, None
            ):  # skip first ip (192.168.1.0)
                if ip not in existing_ips:
                    res.append(f"{ip}/{network.network.prefixlen}")
                    break

        return res

    def add_client(self, id, allowed_ips):
        if not WireguardFile.keys_ready():
            return False

        with UciBackend() as backend:

            interface = get_interface_name()
            cli_name = f"wgclient_{id}"
            section = get_wg_client_type()

            # Check whether it exists
            data = backend.read("network")
            existing_ids = [
                e["name"] for e in get_sections_by_type(data, "network", section)
            ]
            if id in existing_ids:
                return False

            try:
                # wireguard interface is not created
                # don't create the client unless it is created
                get_option_named(
                    data,
                    "network",
                    get_interface_name(),
                    "addresses",
                )
            except UciRecordNotFound:
                # wireguard interface doesn't exist
                return False

            # Client with given name already exists
            if section_exists(data, "network", cli_name):
                return False

            # create the section
            backend.add_section("network", section, cli_name)

            # Get client ip in wireguard network
            inner_ips = self._get_wg_network_client_ips(data, cli_name, section)
            #  merge allowed_ips with ip of the client within WG network
            allowed_ips = inner_ips + allowed_ips

            # Generate keys
            WireguardCmds().generate_client_keys(id)

            # Configure client
            backend.add_section("network", section, cli_name)
            backend.set_option(
                "network",
                interface,
                "public_key",
                WireguardFile.client_pub_content(id).strip(),
            )
            backend.set_option(
                "network",
                interface,
                "preshared_key",
                WireguardFile.client_psk_content(id).strip(),
            )
            backend.replace_list("network", cli_name, "allowed_ips", allowed_ips)
            # TODO this migh be and optional (you may not want to route trafic to the client network)
            backend.set_option(
                "network", cli_name, "route_allowed_ips", store_bool(True)
            )
            backend.set_option("network", cli_name, "disabled", store_bool(False))

        MaintainCommands().restart_network()
        return True

    def export_client(self, id: str) -> typing.Optional[typing.Dict[str, typing.Any]]:
        cli_name = f"wgclient_{id}"

        with UciBackend() as backend:
            uci_data = backend.read("network")
            if not section_exists(uci_data, "network", cli_name):
                return None

        interface = get_interface_name()

        res = {
            "client": {
                "id": id,
                "private-key": WireguardFile.client_key_content(id).strip(),
                "addresses": get_option_named(
                    uci_data, "network", cli_name, "allowed_ips"
                ),  # server expect these address on the client
            },
            "server": {
                "serial-number": CryptoWrapperCmds().get_serial(),
                "address": self._get_wan_address(),
                "public-key": WireguardFile.server_pub_content(),
                "preshared-key": WireguardFile.server_psk_content(),
                "port": int(
                    get_option_named(uci_data, "network", interface, "listen_port")
                ),
                "networks": [str(self._get_lan_addresses(uci_data))]
                + get_option_named(
                    uci_data, "network", get_interface_name(), "addresses"
                ),  # lan addresses + wg addresses
                "dns": [],  # just keep empty for now
            },
        }
        return res

    def set_client(self, id: str, enabled: bool):
        with UciBackend() as backend:

            cli_name = f"wgclient_{id}"

            data = backend.read("network")
            # Client with given name already exists
            if not section_exists(data, "network", cli_name):
                return False

            # create the section
            backend.set_option("network", cli_name, "disabled", store_bool(not enabled))

        MaintainCommands().restart_network()
        return True

    def del_client(self, id):
        with UciBackend() as backend:

            cli_name = f"wgclient_{id}"

            data = backend.read("network")
            # Client with given name already exists
            if not section_exists(data, "network", cli_name):
                return False

            # create the section
            backend.del_section("network", cli_name)

        MaintainCommands().restart_network()
        return True

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
