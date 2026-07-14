#!/usr/bin/env python3
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pynetbox==7.5.0",
#     "requests>=2.33.1",
# ]
# ///

from __future__ import annotations

import argparse
import getpass
import ipaddress
import logging
import os
import time
try:
    import tomllib
except ImportError:
    import tomli as tomllib
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, TypedDict, cast

import pynetbox
import requests
from pynetbox.models.dcim import Devices
from pynetbox.models.ipam import IpAddresses


class LibreDeviceInfo(TypedDict, total=False):
    device_id: str
    hostname: str
    display: str
    location: str


class LibreNMSClient:
    """Encapsulates LibreNMS API interactions and error handling."""

    def __init__(
        self,
        api_url: str,
        token: str,
        verify: bool | str,
        dry_run: bool,
        snmp_config: dict[str, Any] | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/") + "/"
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update({"X-Auth-Token": token})
        self.session.verify = verify
        self.snmp_config = snmp_config or {}

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Wrapper for requests that automatically handles standard LibreNMS errors."""
        url = self.api_url + endpoint.lstrip("/")
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()

        try:
            data: dict[str, Any] = response.json()
        except ValueError:
            return {}

        if data.get("status") == "error":
            raise Exception(f"LibreNMS API Error: {data.get('message')}")
        return data

    def get_devices(self) -> list[dict[str, Any]]:
        return self._request("GET", "")["devices"]

    def create_device(self, hostname: str, display_name: str, location: str | None = None) -> str:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would create LibreNMS device: {hostname} ('{display_name}') at '{location}'"
            )
            return "dry-run-id"

        logging.info(f"Creating new LibreNMS device: {hostname} ('{display_name}') at '{location}'")

        prefer_v3 = self.snmp_config.get("prefer_v3", True)
        v3_config = self.snmp_config.get("v3", {})
        v2c_config = self.snmp_config.get("v2c", {})

        # Support both a single dictionary or an array of dictionaries for multiple SNMPv3 credentials
        v3_configs = []
        if isinstance(v3_config, list):
            v3_configs = v3_config
        elif isinstance(v3_config, dict) and v3_config:
            v3_configs = [v3_config]

        payloads = []

        for v3_cfg in v3_configs:
            auth_name = v3_cfg.get("authname")
            p = {
                "hostname": hostname,
                "display": display_name,
                "version": "v3",
                "authname": auth_name,
                "authpass": v3_cfg.get("authpass"),
                "authalgo": v3_cfg.get("authalgo", "SHA"),
                "cryptopass": v3_cfg.get("cryptopass"),
                "cryptoalgo": v3_cfg.get("cryptoalgo", "AES"),
                "seclevel": v3_cfg.get("security_level", "authPriv"),
            }
            if location:
                p["location"] = location
                p["override_sysLocation"] = True
            payloads.append({
                "version": f"v3 ({auth_name})" if auth_name else "v3",
                "payload": p
            })

        if v2c_config:
            p = {
                "hostname": hostname,
                "display": display_name,
                "version": "v2c",
                "community": v2c_config.get("community", "public"),
            }
            if location:
                p["location"] = location
                p["override_sysLocation"] = True
            payloads.append({
                "version": "v2c",
                "payload": p
            })

        if not prefer_v3:
            payloads.reverse()

        last_error = None
        for item in payloads:
            try:
                logging.info(f"Attempting to add device '{hostname}' using SNMP {item['version']}")
                res = self._request("POST", "", json=item["payload"])
                device_id = str(res["devices"][0]["device_id"])
                logging.info(f"Successfully added device '{hostname}' with SNMP {item['version']}. ID: {device_id}")
                return device_id
            except Exception as e:
                logging.warning(f"Failed to add device '{hostname}' using SNMP {item['version']}: {e}")
                last_error = e

        raise Exception(f"All SNMP enrolment attempts failed for '{hostname}'. Last error: {last_error}")

    def remove_overwrite_ip(self, device_id: str, hostname: str) -> None:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would remove deprecated overwrite IP for '{hostname}'"
            )
            return

        logging.info(f"Removing deprecated overwrite IP for '{hostname}'")
        self._request(
            "PATCH", str(device_id), json={"field": "overwrite_ip", "data": None}
        )

    def get_netbox_component(self, hostname: str) -> dict[str, Any]:
        res = self._request("GET", f"{hostname}/components?type=netbox_id")
        return res.get("components", {})

    def unlink_component(
        self, device_id: str, component_id: str, netbox_id: str, hostname: str
    ) -> None:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would unlink Netbox ID '{netbox_id}' from '{hostname}'"
            )
            return

        logging.info(
            f"Unlinking deleted/decommissioned Netbox ID '{netbox_id}' from '{hostname}'"
        )
        self._request("DELETE", f"{device_id}/components/{component_id}")

    def link_device(
        self, libnms_id: str, libnms_hostname: str, netbox_id: str, netbox_name: str
    ) -> None:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would link '{libnms_hostname}' to NetBox ID {netbox_id} ('{netbox_name}')"
            )
            return

        logging.info(
            f"Linking '{libnms_hostname}' to NetBox ID {netbox_id} ('{netbox_name}')"
        )
        res = self._request("POST", f"{libnms_id}/components/netbox_id")
        component_id = list(res["components"])[0]

        component_data = {
            str(component_id): {
                "type": "netbox_id",
                "label": str(netbox_id),
                "status": 1,
                "ignore": 0,
                "disabled": 0,
                "error": "",
            }
        }
        self._request("PUT", f"{libnms_id}/components", json=component_data)

    def rename_device(self, libnms_id: str, old_name: str, new_name: str) -> None:
        if self.dry_run:
            logging.info(f"[DRY RUN] Would rename '{old_name}' to '{new_name}'")
            return
        logging.info(f"Renaming '{old_name}' to '{new_name}'")
        self._request("PATCH", f"{libnms_id}/rename/{new_name}")

    def update_display_name(
        self, libnms_id: str, hostname: str, old_display: str, new_display: str
    ) -> None:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would update display name for '{hostname}' from '{old_display}' to '{new_display}'"
            )
            return
        logging.info(
            f"Updating display name for '{hostname}' from '{old_display}' to '{new_display}'"
        )
        self._request(
            "PATCH", str(libnms_id), json={"field": "display", "data": new_display}
        )

    def update_location(
        self, libnms_id: str, hostname: str, old_location: str, new_location: str
    ) -> None:
        if self.dry_run:
            logging.info(
                f"[DRY RUN] Would update location for '{hostname}' from '{old_location}' to '{new_location}'"
            )
            return
        logging.info(
            f"Updating location for '{hostname}' from '{old_location}' to '{new_location}'"
        )
        self._request(
            "PATCH", str(libnms_id), json={"field": "location", "data": new_location}
        )
        self._request(
            "PATCH", str(libnms_id), json={"field": "override_sysLocation", "data": True}
        )


def fetch_netbox_devices(
    nb: pynetbox.api, nb_config: dict[str, Any], netbox_roles: list[str]
) -> list[Devices]:
    tenant_slugs = [str(t) for t in nb_config.get("tenants", []) if not str(t).isdigit()]
    tenant_ids = [int(t) for t in nb_config.get("tenants", []) if str(t).isdigit()]

    devices_init: list[Devices] = []
    statuses: list[str] = nb_config.get("statuses", ["active"])
    device_types = nb_config.get("device_types", [])
    platforms = nb_config.get("platforms", [])

    # Build standard filters
    query_params: dict[str, Any] = {"status": statuses}
    if netbox_roles:
        query_params["role"] = netbox_roles
    if device_types:
        query_params["device_type"] = device_types
    if platforms:
        query_params["platform"] = platforms

    if tenant_slugs:
        devices_init.extend(
            nb.dcim.devices.filter(
                tenant=tenant_slugs, **query_params
            )
        )
    if tenant_ids:
        devices_init.extend(
            nb.dcim.devices.filter(
                tenant_id=tenant_ids, **query_params
            )
        )

    # If no tenant constraints are configured
    if not tenant_slugs and not tenant_ids:
        devices_init.extend(
            nb.dcim.devices.filter(**query_params)
        )

    if nb_config.get("override_pull_ids"):
        devices_init.extend(nb.dcim.devices.filter(id=nb_config["override_pull_ids"]))
    return devices_init


def filter_netbox_devices(devices_init: list[Devices]) -> dict[str, Devices]:
    valid_devices: dict[str, Devices] = {}
    for device in devices_init:
        if device.primary_ip4 or device.oob_ip:
            valid_devices[str(device.id)] = device
        else:
            logging.warning(f"Device {device} has no primary IPv4 or OOB IP")
    return valid_devices


def get_netbox_roles(nb: pynetbox.api, nb_config: dict[str, Any]) -> list[str]:
    netbox_roles = []
    roles = nb_config.get("roles", [])
    if roles:
        for r in roles:
            try:
                role_obj = nb.dcim.device_roles.get(slug=r)
                if role_obj:
                    netbox_roles.append(str(role_obj.slug))
                else:
                    logging.warning(f"Netbox Device Role with slug '{r}' not found.")
            except Exception as e:
                logging.warning(f"Error fetching role slug '{r}': {e}")

    fuzzy_roles = nb_config.get("fuzzy_roles", [])
    if fuzzy_roles:
        for fuzzy in fuzzy_roles:
            try:
                netbox_roles.extend(
                    [str(role.slug) for role in nb.dcim.device_roles.filter(fuzzy)]
                )
            except Exception as e:
                logging.warning(f"Error filtering fuzzy roles '{fuzzy}': {e}")

    return netbox_roles


def fetch_libnms_mapping(
    client: LibreNMSClient,
    netbox_devices: dict[str, Devices],
    single_device_mode: bool = False,
) -> tuple[dict[str, LibreDeviceInfo], dict[str, LibreDeviceInfo]]:
    """Maps LibreNMS devices to NetBox IDs, identifying linked and unlinked devices."""
    linked: dict[str, LibreDeviceInfo] = {}
    unlinked: dict[str, LibreDeviceInfo] = {}

    for device in client.get_devices():
        dev_id = str(device["device_id"])
        hostname = str(device["hostname"])
        display = str(device["display"])
        location = str(device.get("location") or "")

        try:
            if device.get("overwrite_ip"):
                client.remove_overwrite_ip(dev_id, hostname)

            components = client.get_netbox_component(hostname)

            if not components:
                unlinked[dev_id] = {
                    "device_id": dev_id,
                    "hostname": hostname,
                    "display": display,
                    "location": location,
                }
                continue

            if len(components) > 1:
                raise ValueError(
                    f"Expected 1 Netbox ID attached to '{hostname}', got {len(components)}"
                )

            component_id, component = next(iter(components.items()))
            netbox_id = str(component["label"])

            if netbox_id not in netbox_devices:
                if single_device_mode:
                    # In single device testing mode, do NOT unlink other already-linked devices
                    continue
                # Device must have been filtered out, or deleted/decommisioned. Unlink it.
                client.unlink_component(dev_id, component_id, netbox_id, hostname)
                unlinked[dev_id] = {
                    "device_id": dev_id,
                    "hostname": hostname,
                    "display": display,
                    "location": location,
                }
            else:
                linked[netbox_id] = {
                    "device_id": dev_id,
                    "display": display,
                    "hostname": hostname,
                    "location": location,
                }
        except Exception:
            logging.exception(
                f"Failed to process LibreNMS device mapping for '{hostname}'. Skipping device."
            )
            continue

    return linked, unlinked


def get_netbox_location(device: Devices) -> str:
    """Extracts region and site hierarchy as a location string from pynetbox Device."""
    site = getattr(device, "site", None)
    if not site:
        return ""

    site_name = getattr(site, "name", "") or ""
    region = getattr(site, "region", None)
    region_name = ""
    if region:
        region_name = getattr(region, "name", "") or ""

    if region_name and site_name:
        return f"{region_name} / {site_name}"
    return site_name or region_name


def sync_device(
    client: LibreNMSClient,
    libnms_info: LibreDeviceInfo,
    nb_hostname: str,
    nb_name: str,
    nb_location: str | None = None,
) -> None:
    """Checks and updates LibreNMS device hostnames, display names, and locations if out of sync."""
    libnms_id = libnms_info["device_id"]

    if libnms_info["hostname"].lower() != nb_hostname.lower():
        client.rename_device(libnms_id, libnms_info["hostname"], nb_hostname)
        libnms_info["hostname"] = nb_hostname

    if libnms_info["display"] != nb_name:
        client.update_display_name(
            libnms_id, libnms_info["hostname"], libnms_info["display"], nb_name
        )
        libnms_info["display"] = nb_name

    if nb_location is not None:
        old_location = libnms_info.get("location", "")
        if old_location != nb_location:
            client.update_location(
                libnms_id, libnms_info["hostname"], old_location, nb_location
            )
            libnms_info["location"] = nb_location


def get_netbox_ip_and_hostname(device: Devices, test=None) -> tuple[str, str]:
    """Extracts preferred IP and hostname from a NetBox device."""
    target_ip = cast(
        IpAddresses, device.oob_ip if device.oob_ip else device.primary_ip4
    )
    target_ip_address = str(target_ip.address)

    hostname = str(
        getattr(target_ip, "dns_name", None)
        or target_ip_address.split("/", maxsplit=1)[0]
    )
    ip_addr = target_ip_address.split("/", maxsplit=1)[0]
    return ip_addr, hostname


def sync_netbox_librenms(
    libnms: LibreNMSClient,
    netbox_devices: dict[str, Devices],
    linked_libnms: dict[str, LibreDeviceInfo],
    unlinked_libnms: dict[str, LibreDeviceInfo],
) -> dict[str, str]:
    """Checks and syncs NetBox devices with LibreNMS. Returns a dictionary of failed device names and error reasons."""
    failures: dict[str, str] = {}
    for nb_id, nb_device in netbox_devices.items():
        try:
            nb_ip, nb_hostname = get_netbox_ip_and_hostname(nb_device)
            nb_name = str(nb_device.name)
            nb_location = get_netbox_location(nb_device)

            if nb_id in linked_libnms:
                sync_device(libnms, linked_libnms[nb_id], nb_hostname, nb_name, nb_location)
            else:
                match_found = False
                # Iteratively search for a device which might match
                for lib_id, lib_dev in list(unlinked_libnms.items()):
                    if (
                        lib_dev["hostname"] in (nb_hostname, nb_name, nb_ip)
                        or lib_dev["display"] == nb_name
                    ):
                        libnms.link_device(lib_id, lib_dev["hostname"], nb_id, nb_name)
                        sync_device(libnms, lib_dev, nb_hostname, nb_name, nb_location)
                        del unlinked_libnms[lib_id]
                        linked_libnms[nb_id] = {
                            "device_id": lib_id,
                            "display": lib_dev["display"],
                            "hostname": lib_dev["hostname"],
                            "location": lib_dev.get("location", ""),
                        }
                        match_found = True
                        break

                if not match_found:
                    # Still not found: try to create it
                    new_libnms_id = libnms.create_device(nb_hostname, nb_name, nb_location)
                    if not libnms.dry_run:
                        libnms.link_device(new_libnms_id, nb_hostname, nb_id, nb_name)
                        # Rate limit: Wait 1.0s to avoid overwhelming LibreNMS API with concurrent SNMP probes
                        time.sleep(1.0)
                    linked_libnms[nb_id] = {
                        "device_id": new_libnms_id,
                        "display": nb_name,
                        "hostname": nb_hostname,
                        "location": nb_location,
                    }
        except Exception as e:
            err_msg = str(e)
            logging.exception(
                f"Failed to sync Netbox device '{nb_device}'. Skipping device. Error: {err_msg}"
            )
            failures[str(nb_device.name)] = err_msg
            continue
    return failures


def attempt_find_orphans(
    nb: pynetbox.api, unlinked_devices: dict[str, LibreDeviceInfo]
) -> dict[str, list[Devices]]:
    """Attempts to match unlinked LibreNMS devices to NetBox devices which were not fetched."""
    orphans_and_candidates: dict[str, list[Devices]] = {}
    for libnms_id, dev in unlinked_devices.items():
        candidates: set[Devices] = set()

        # Check via IP
        nb_ip = cast(
            IpAddresses | None, nb.ipam.ip_addresses.get(dns_name=dev["hostname"])
        )
        if not nb_ip:
            try:
                ipaddress.ip_address(dev["hostname"])
                nb_ip = cast(
                    IpAddresses | None,
                    nb.ipam.ip_addresses.get(address=dev["hostname"]),
                )
            except ValueError:
                pass
        if nb_ip:
            candidates.update(nb.dcim.devices.filter(primary_ip4_id=nb_ip.id))
            candidates.update(nb.dcim.devices.filter(oob_ip_id=nb_ip.id))

        # Check via display name -> netbox name
        if dev["display"]:
            candidates.update(nb.dcim.devices.filter(name=dev["display"]))

        if candidates:
            resolved = [
                {
                    "id": c.id,
                    "name": c.name,
                    "role": c.role.slug if c.role else "None",
                    "tenant": c.tenant.slug if c.tenant else "None",
                }
                for c in candidates
            ]
            logging.warning(
                f"Orphaned LibreNMS device {libnms_id} ('{dev['hostname']}') might map to NetBox Device(s): {resolved}\n"
                "Check Status and Role configs—are they excluded intentionally?"
            )
            orphans_and_candidates[libnms_id] = list(candidates)
        else:
            logging.warning(
                f"Orphaned LibreNMS device {libnms_id} ('{dev['hostname']}') not found in NetBox."
            )
            orphans_and_candidates[libnms_id] = []
    return orphans_and_candidates


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync NetBox devices to LibreNMS.")
    parser.add_argument(
        "--device",
        type=str,
        help="Sync a single device by its NetBox name or numerical ID, bypassing standard filters (for testing).",
    )
    args = parser.parse_args()

    config_path = Path(__file__).resolve().parent / "config.toml"
    with config_path.open("rb") as f:
        config = tomllib.load(f)

    nb_config = config["netbox"]

    rfh = RotatingFileHandler(
        filename=config["general"]["log_file"], maxBytes=5 * 1024 * 1024, backupCount=1
    )
    sh = logging.StreamHandler()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s:%(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[rfh, sh],
    )

    logging.info("Script beginning")

    # Securely retrieve NetBox Token
    nb_token = os.environ.get("NETBOX_API_TOKEN") or nb_config.get("token")
    if not nb_token:
        nb_token = getpass.getpass("Enter NetBox API Token: ").strip()
        if not nb_token:
            raise ValueError("NetBox API Token cannot be empty.")

    # Securely retrieve LibreNMS Token
    lnms_token = os.environ.get("LIBRENMS_API_TOKEN") or config["librenms"].get("token")
    if not lnms_token:
        lnms_token = getpass.getpass("Enter LibreNMS API Token: ").strip()
        if not lnms_token:
            raise ValueError("LibreNMS API Token cannot be empty.")

    nb = pynetbox.api(nb_config["api"].rstrip("/") + "/", token=nb_token)
    # Set TLS verification for NetBox API requests
    nb.http_session.verify = nb_config.get("ca_verify", True)

    libnms = LibreNMSClient(
        api_url=config["librenms"]["api"],
        token=lnms_token,
        verify=config["librenms"].get("ca_verify", True),
        dry_run=config["general"].get("dry_run", False),
        snmp_config=config.get("snmp"),
    )
    single_device_mode = bool(args.device)
    if single_device_mode:
        logging.info(f"Single device pull requested for target: {args.device}")
        logging.info("[Step 1/6] (Bypassed) Loading roles from Netbox")
        logging.info("[Step 2/6] Loading single target device from Netbox")
        device_to_pull = None
        # Resolve by ID if numeric
        if args.device.isdigit():
            logging.info(f"Input '{args.device}' is numeric. Attempting to resolve as NetBox Device ID first...")
            try:
                device_to_pull = nb.dcim.devices.get(id=int(args.device))
                if device_to_pull:
                    logging.info(f"Successfully resolved '{args.device}' as NetBox Device ID.")
            except Exception as e:
                logging.warning(f"Failed to fetch device by ID '{args.device}': {e}")

        # If not found yet or not numeric, resolve by name
        if not device_to_pull:
            try:
                devices_found = list(nb.dcim.devices.filter(name=args.device))
                if devices_found:
                    exact_matches = [d for d in devices_found if str(d.name).lower() == args.device.lower()]
                    if exact_matches:
                        device_to_pull = exact_matches[0]
                    else:
                        if len(devices_found) == 1:
                            device_to_pull = devices_found[0]
                            logging.warning(
                                f"No exact case-insensitive name match found for '{args.device}'. "
                                f"Using the single partial match returned: '{device_to_pull.name}' (ID: {device_to_pull.id})."
                            )
                        else:
                            match_names = [f"'{d.name}' (ID: {d.id})" for d in devices_found]
                            logging.error(
                                f"Multiple matches found for '{args.device}' in NetBox: {', '.join(match_names)}. "
                                "Please specify the exact name or a specific device ID to avoid ambiguity."
                            )
                            return
            except Exception as e:
                logging.warning(f"Failed to fetch device by name '{args.device}': {e}")

        if not device_to_pull:
            logging.error(f"Device '{args.device}' not found in NetBox. Exiting.")
            return

        devices_init = [device_to_pull]
        devices_init_count = 1
        logging.info(f"Found device in NetBox: {device_to_pull.name} (ID: {device_to_pull.id})")
    else:
        logging.info("[Step 1/6] Loading roles from Netbox")
        netbox_roles = get_netbox_roles(nb, nb_config)
        logging.info(f"Found Roles: {netbox_roles}")

        logging.info("[Step 2/6] Loading devices matching tenants/roles from Netbox")
        devices_init = fetch_netbox_devices(nb, nb_config, netbox_roles)
        devices_init_count = len(devices_init)
        logging.info(f"Found {devices_init_count} matching devices")

    logging.info("[Step 3/6] Filtering out Netbox devices without a primary/OOB IP")
    netbox_devices = filter_netbox_devices(devices_init)
    netbox_devices_count = len(netbox_devices)
    logging.info(
        f"Filtered out {devices_init_count - netbox_devices_count} device(s). Now left with {netbox_devices_count} devices."
    )
    if not netbox_devices:
        logging.warning("No devices left after IP filtering. Exiting.")
        return

    logging.info("[Step 4/6] Fetching map of Netbox/LibreNMS devices")
    linked_libnms, unlinked_libnms = fetch_libnms_mapping(
        client=libnms, netbox_devices=netbox_devices, single_device_mode=single_device_mode
    )
    initial_linked_count = len(linked_libnms)
    initial_unlinked_count = len(unlinked_libnms)
    logging.info(
        f"Found {initial_linked_count} devices already linked to Netbox, and {initial_unlinked_count} not yet linked"
    )

    logging.info("[Step 5/6] Checking Netbox devices against LibreNMS, and syncing")
    failures = sync_netbox_librenms(libnms, netbox_devices, linked_libnms, unlinked_libnms)
    final_linked_count = len(linked_libnms)
    final_unlinked_count = len(unlinked_libnms)
    logging.info(
        f"{initial_linked_count - final_linked_count} newly linked devices, "
        f"consisting of {initial_unlinked_count - final_unlinked_count} previously unlinked devices that are now linked, "
        f"and {final_linked_count + final_unlinked_count - initial_linked_count - initial_unlinked_count} newly-created devices."
    )

    if failures:
        logging.warning("=" * 80)
        logging.warning(f"SYNC WARNING: {len(failures)} device(s) failed to sync:")
        for name, err in failures.items():
            logging.warning(f"  - {name}: {err}")
        logging.warning("=" * 80)

    if single_device_mode:
        logging.info("[Step 6/6] (Bypassed) Checking for potential orphans in single-device mode")
    else:
        logging.info(
            f"[Step 6/6] Checking {final_unlinked_count} remaining unlinked devices for potential orphans"
        )
        # TODO: Do something with orphans remaining
        # For example, add to a LibreNMS device group for visibility
        orphans_and_candidates = attempt_find_orphans(nb, unlinked_libnms)  # noqa: F841

    logging.info("Script finished")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Script failed with an unhandled exception")
        raise
