#!/usr/bin/env python3
"""
NetBox to LibreNMS Real-Time Sync (Webhook Receiver)

This script provides a FastAPI endpoint that receives webhook events from NetBox,
validates payload signatures, and automatically provisions or syncs devices in LibreNMS
by reusing the LibreNMSClient from pull_netbox.py.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
try:
    import tomllib
except ImportError:
    import tomli as tomllib
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status

# Import LibreNMSClient and model types from pull_netbox.py
from pull_netbox import LibreDeviceInfo, LibreNMSClient

# Setup FastAPI App
app = FastAPI(
    title="NetBox to LibreNMS Webhook Receiver",
    description="Real-time event-driven monitoring enrollment.",
    version="1.0.0",
)

# Load configuration file
CONFIG_PATH = Path(__file__).resolve().parent / "config.toml"
try:
    with CONFIG_PATH.open("rb") as f:
        config = tomllib.load(f)
except Exception as e:
    raise RuntimeError(f"Failed to load config.toml from {CONFIG_PATH}: {e}")

nb_config = config.get("netbox", {})
lnms_config = config.get("librenms", {})
webhook_config = config.get("webhook", {})
general_config = config.get("general", {})

# Setup logging
log_file = general_config.get("log_file", "webhook_receiver.log")
handlers: list[logging.Handler] = [logging.StreamHandler()]

try:
    rfh = RotatingFileHandler(
        filename=log_file, maxBytes=5 * 1024 * 1024, backupCount=1, encoding="utf-8"
    )
    handlers.append(rfh)
except Exception as e:
    print(f"Warning: Failed to initialize file logger at {log_file} ({e}). Falling back to stdout-only logging.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s:%(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=handlers,
)

logging.info("Webhook receiver service initializing...")

# Retrieve credentials securely (supports systemd-creds, Environment Variables, and config.toml fallback)
credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
lnms_token = ""
secret_key = ""

if credentials_dir:
    cred_path = Path(credentials_dir)
    if (cred_path / "librenms_token").exists():
        logging.info("Loading LibreNMS API Token from systemd-creds vault.")
        lnms_token = (cred_path / "librenms_token").read_text(encoding="utf-8").strip()
    if (cred_path / "webhook_secret_key").exists():
        logging.info("Loading HMAC Webhook Secret Key from systemd-creds vault.")
        secret_key = (cred_path / "webhook_secret_key").read_text(encoding="utf-8").strip()

if not lnms_token:
    lnms_token = os.environ.get("LIBRENMS_API_TOKEN") or lnms_config.get("token")

if not lnms_token:
    raise ValueError(
        "LibreNMS API Token cannot be empty. Please configure it in config.toml, "
        "set the LIBRENMS_API_TOKEN environment variable, or configure systemd-creds."
    )

if not secret_key:
    secret_key = os.environ.get("WEBHOOK_SECRET_KEY") or webhook_config.get("secret_key", "").strip()

# Initialize LibreNMS client
libnms = LibreNMSClient(
    api_url=lnms_config["api"],
    token=lnms_token,
    verify=lnms_config.get("ca_verify", True),
    dry_run=general_config.get("dry_run", False),
    snmp_config=config.get("snmp"),
)

if secret_key:
    logging.info("HMAC-SHA512 Webhook signature verification is ENABLED.")
else:
    logging.warning("HMAC signature verification is DISABLED. Please set secret_key in config.toml, environment, or systemd-creds for production use.")


def extract_ip_and_hostname(data: dict[str, Any]) -> tuple[str, str] | None:
    """Extracts preferred IP and hostname from NetBox webhook device representation."""
    ip_obj = data.get("oob_ip") or data.get("primary_ip4") or data.get("primary_ip")
    if not ip_obj:
        return None

    address_str = ip_obj.get("address")
    if not address_str:
        return None

    ip_addr = address_str.split("/", maxsplit=1)[0]
    hostname = ip_obj.get("dns_name") or ip_obj.get("dns") or ip_addr
    return ip_addr, hostname


def device_matches_filters(data: dict[str, Any], nb_conf: dict[str, Any]) -> bool:
    """Checks if NetBox device data matches configured synchronization filters."""
    # 1. Check Status
    allowed_statuses = nb_conf.get("statuses", ["active"])
    status_obj = data.get("status")
    status_val = ""
    if isinstance(status_obj, dict):
        status_val = status_obj.get("value") or status_obj.get("slug") or ""
    elif isinstance(status_obj, str):
        status_val = status_obj

    if status_val not in allowed_statuses:
        logging.info(f"Filtered: Status '{status_val}' is not in allowed list {allowed_statuses}")
        return False

    # 2. Check Tenant
    tenants = nb_conf.get("tenants", [])
    if tenants:
        tenant_obj = data.get("tenant")
        if not tenant_obj:
            logging.info("Filtered: Device has no tenant, but tenant filters are configured.")
            return False
        tenant_slug = tenant_obj.get("slug")
        tenant_id = tenant_obj.get("id")

        match = False
        for t in tenants:
            if str(t).isdigit() and int(t) == tenant_id:
                match = True
                break
            elif str(t) == tenant_slug:
                match = True
                break
        if not match:
            logging.info(f"Filtered: Tenant '{tenant_slug}' does not match configured tenants {tenants}.")
            return False

    # 3. Check Device Role
    roles = nb_conf.get("roles", [])
    fuzzy_roles = nb_conf.get("fuzzy_roles", [])
    if roles or fuzzy_roles:
        role_obj = data.get("role") or data.get("device_role")
        if not role_obj:
            logging.info("Filtered: Device has no role, but role filters are configured.")
            return False
        role_slug = role_obj.get("slug", "")

        role_match = False
        if roles and role_slug in roles:
            role_match = True
        elif fuzzy_roles:
            for fuzzy in fuzzy_roles:
                if fuzzy in role_slug:
                    role_match = True
                    break
        if not role_match:
            logging.info(f"Filtered: Role '{role_slug}' does not match configured roles/fuzzy_roles.")
            return False

    # 4. Check Device Type
    device_types = nb_conf.get("device_types", [])
    if device_types:
        dt_obj = data.get("device_type")
        if not dt_obj:
            logging.info("Filtered: Device has no device_type, but device_type filters are configured.")
            return False
        dt_slug = dt_obj.get("slug")
        if dt_slug not in device_types:
            logging.info(f"Filtered: Device Type '{dt_slug}' is not in allowed list {device_types}.")
            return False

    # 5. Check Platform
    platforms = nb_conf.get("platforms", [])
    if platforms:
        platform_obj = data.get("platform")
        if not platform_obj:
            logging.info("Filtered: Device has no platform, but platform filters are configured.")
            return False
        platform_slug = platform_obj.get("slug")
        if platform_slug not in platforms:
            logging.info(f"Filtered: Platform '{platform_slug}' is not in allowed list {platforms}.")
            return False

    return True


def extract_location(data: dict[str, Any]) -> str:
    """Extracts region and site hierarchy as a location string."""
    site_obj = data.get("site")
    if not site_obj or not isinstance(site_obj, dict):
        return ""

    site_name = site_obj.get("name") or ""
    region_obj = site_obj.get("region")
    region_name = ""
    if region_obj and isinstance(region_obj, dict):
        region_name = region_obj.get("name") or ""

    if region_name and site_name:
        return f"{region_name} / {site_name}"
    return site_name or region_name


def sync_device_fields(
    libnms_info: LibreDeviceInfo,
    nb_hostname: str,
    nb_name: str,
    nb_location: str | None = None,
) -> None:
    """Helper to call client sync methods for hostname, display name, and location updates."""
    libnms_id = libnms_info["device_id"]

    if libnms_info["hostname"].lower() != nb_hostname.lower():
        libnms.rename_device(libnms_id, libnms_info["hostname"], nb_hostname)
        libnms_info["hostname"] = nb_hostname

    if libnms_info["display"] != nb_name:
        libnms.update_display_name(
            libnms_id, libnms_info["hostname"], libnms_info["display"], nb_name
        )
        libnms_info["display"] = nb_name

    if nb_location is not None:
        old_location = libnms_info.get("location", "")
        if old_location != nb_location:
            libnms.update_location(
                libnms_id, libnms_info["hostname"], old_location, nb_location
            )
            libnms_info["location"] = nb_location


def find_matching_libre_device(
    devices: list[dict[str, Any]],
    nb_hostname: str,
    nb_ip: str,
    nb_name: str,
    pre_hostname: str | None = None,
    pre_ip: str | None = None,
    pre_name: str | None = None,
) -> dict[str, Any] | None:
    """Finds a matching LibreNMS device by checking current and old hostname/IP/display name."""
    lookups = {nb_hostname.lower(), nb_ip, nb_name}
    if pre_hostname:
        lookups.add(pre_hostname.lower())
    if pre_ip:
        lookups.add(pre_ip)
    if pre_name:
        lookups.add(pre_name)

    # Discard empty strings or None to avoid matching empty fields in malformed LibreNMS devices
    lookups = {x for x in lookups if x}

    for dev in devices:
        hostname = str(dev["hostname"])
        display = str(dev["display"])
        if hostname.lower() in lookups or hostname in lookups or display in lookups:
            return dev
    return None


async def process_sync_device(
    nb_id: str,
    nb_hostname: str,
    nb_name: str,
    nb_ip: str,
    payload: dict[str, Any],
) -> None:
    """Handles device creation, linking, and renaming when receiving a create/update webhook."""
    # Extract current location from NetBox device details
    nb_location = extract_location(payload.get("data", {}))

    # Try to extract previous state from snapshots to catch renames/IP modifications
    pre_hostname, pre_ip, pre_name = None, None, None
    snapshots = payload.get("snapshots")
    if isinstance(snapshots, dict) and "pre" in snapshots:
        pre_data = snapshots["pre"]
        if isinstance(pre_data, dict):
            pre_name = pre_data.get("name")
            pre_ip_info = extract_ip_and_hostname(pre_data)
            if pre_ip_info:
                pre_ip, pre_hostname = pre_ip_info

    try:
        devices = libnms.get_devices()
    except Exception as e:
        logging.error(f"Failed to fetch devices from LibreNMS: {e}")
        return

    # Find if there is a matching LibreNMS device
    target_dev = find_matching_libre_device(
        devices,
        nb_hostname=nb_hostname,
        nb_ip=nb_ip,
        nb_name=nb_name,
        pre_hostname=pre_hostname,
        pre_ip=pre_ip,
        pre_name=pre_name,
    )

    if target_dev:
        dev_id = str(target_dev["device_id"])
        hostname = str(target_dev["hostname"])
        display = str(target_dev["display"])
        location = str(target_dev.get("location") or "")

        libnms_info: LibreDeviceInfo = {
            "device_id": dev_id,
            "hostname": hostname,
            "display": display,
            "location": location,
        }

        # Check existing link components
        try:
            components = libnms.get_netbox_component(hostname)
        except Exception as e:
            logging.warning(f"Failed to fetch components for '{hostname}': {e}")
            components = {}

        if components:
            component_id, component = next(iter(components.items()))
            linked_nb_id = str(component["label"])

            if linked_nb_id == nb_id:
                # Device is already linked correctly. Sync fields.
                sync_device_fields(libnms_info, nb_hostname, nb_name, nb_location)
            else:
                # Linked to a different NetBox ID! Break link and re-link.
                logging.warning(
                    f"LibreNMS device '{hostname}' is linked to NetBox ID {linked_nb_id}, "
                    f"but we received a webhook for NetBox ID {nb_id}. Re-linking..."
                )
                libnms.unlink_component(dev_id, component_id, linked_nb_id, hostname)
                libnms.link_device(dev_id, hostname, nb_id, nb_name)
                sync_device_fields(libnms_info, nb_hostname, nb_name, nb_location)
        else:
            # Matches hostname/IP but has no NetBox link component yet.
            logging.info(f"LibreNMS device '{hostname}' exists but is not linked to NetBox ID {nb_id}. Linking...")
            libnms.link_device(dev_id, hostname, nb_id, nb_name)
            sync_device_fields(libnms_info, nb_hostname, nb_name, nb_location)
    else:
        # No matching device in LibreNMS. Let's create and link.
        logging.info(f"No matching LibreNMS device found for '{nb_hostname}' (ID: {nb_id}). Enrolling...")
        try:
            new_id = libnms.create_device(nb_hostname, nb_name, nb_location)
            if not libnms.dry_run:
                libnms.link_device(new_id, nb_hostname, nb_id, nb_name)
            logging.info(f"Successfully enrolled and linked LibreNMS device ID {new_id} for '{nb_hostname}'")
        except Exception as e:
            logging.error(f"Failed to enroll device '{nb_hostname}' in LibreNMS: {e}")


async def process_delete_device(
    nb_id: str,
    nb_hostname: str,
    nb_name: str,
    nb_ip: str,
    payload: dict[str, Any],
) -> None:
    """Handles unlinking when a device is deleted or status becomes inactive/unmonitored."""
    pre_hostname, pre_ip, pre_name = None, None, None
    snapshots = payload.get("snapshots")
    if isinstance(snapshots, dict) and "pre" in snapshots:
        pre_data = snapshots["pre"]
        if isinstance(pre_data, dict):
            pre_name = pre_data.get("name")
            pre_ip_info = extract_ip_and_hostname(pre_data)
            if pre_ip_info:
                pre_ip, pre_hostname = pre_ip_info

    try:
        devices = libnms.get_devices()
    except Exception as e:
        logging.error(f"Failed to fetch devices from LibreNMS: {e}")
        return

    target_dev = find_matching_libre_device(
        devices,
        nb_hostname=nb_hostname,
        nb_ip=nb_ip,
        nb_name=nb_name,
        pre_hostname=pre_hostname,
        pre_ip=pre_ip,
        pre_name=pre_name,
    )

    if target_dev:
        dev_id = str(target_dev["device_id"])
        hostname = str(target_dev["hostname"])

        try:
            components = libnms.get_netbox_component(hostname)
        except Exception as e:
            logging.warning(f"Failed to fetch components for '{hostname}': {e}")
            components = {}

        for component_id, component in components.items():
            linked_nb_id = str(component["label"])
            if linked_nb_id == nb_id:
                logging.info(f"Unlinking component ID {component_id} (NetBox ID {nb_id}) from LibreNMS device '{hostname}'")
                libnms.unlink_component(dev_id, component_id, nb_id, hostname)
                break
    else:
        logging.info(f"Unlink skipped: no matching LibreNMS device found for ID {nb_id} ({nb_hostname})")


@app.post("/webhook")
async def handle_webhook(
    request: Request,
    x_hook_signature: str = Header(None, alias="X-Hook-Signature"),
) -> dict[str, str]:
    """Endpoint for processing NetBox event-driven webhooks."""
    body = await request.body()

    # 1. HMAC Signature Verification
    if secret_key:
        if not x_hook_signature:
            logging.warning("Rejected payload: Missing 'X-Hook-Signature' header.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing webhook signature header.",
            )

        computed = hmac.new(
            secret_key.encode("utf-8"),
            body,
            hashlib.sha512
        ).hexdigest()

        if not hmac.compare_digest(computed, x_hook_signature):
            logging.warning("Rejected payload: HMAC signature verification failed.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature.",
            )

    # 2. Parse payload JSON
    try:
        payload = await request.json()
    except Exception as e:
        logging.error(f"Malformed request body received: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON body.",
        )

    event = payload.get("event")
    model = payload.get("model") or payload.get("object_type")
    data = payload.get("data")

    if not event or not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing event or data payload attributes.",
        )

    # Resilient model matching to support both older NetBox models ("device")
    # and newer NetBox models ("dcim.device") under either "model" or "object_type" keys.
    is_device = False
    if model:
        model_str = str(model).lower()
        if model_str == "device" or model_str == "dcim.device" or model_str.endswith(".device"):
            is_device = True

    if not is_device:
        logging.info(f"Event ignored: model/object_type is '{model}' (we only monitor 'device').")
        return {"status": "ignored", "message": f"Model '{model}' is not supported."}

    nb_id = str(data.get("id"))
    nb_name = str(data.get("name", "Unknown-Device"))

    # Extract current IP configurations
    ip_info = extract_ip_and_hostname(data)
    nb_ip, nb_hostname = ip_info if ip_info else (None, None)

    # 3. Process Delete Event
    if event == "deleted":
        if not nb_hostname:
            # Fallback to name if IP addresses are fully erased from deleted model data
            nb_hostname = nb_name
            nb_ip = ""
        logging.info(f"Received delete webhook for NetBox Device ID {nb_id} ('{nb_name}')")
        await process_delete_device(nb_id, nb_hostname, nb_name, nb_ip or "", payload)
        return {"status": "processed", "action": "delete/unlink"}

    # 4. Process Sync/Enrol (created or updated)
    logging.info(f"Received webhook event '{event}' for NetBox Device ID {nb_id} ('{nb_name}')")

    # If the device matches synchronization filters
    if device_matches_filters(data, nb_config):
        if not ip_info:
            logging.warning(f"Device ID {nb_id} ('{nb_name}') matches filters, but has no primary or OOB IP address.")
            return {"status": "failed", "message": "Filter match, but device is missing IP."}

        await process_sync_device(nb_id, nb_hostname or "", nb_name, nb_ip or "", payload)
        return {"status": "processed", "action": "sync"}
    else:
        # If a device doesn't match filters but was previously active/linked, we should unlink it
        logging.info(f"Device ID {nb_id} ('{nb_name}') does not match filters. Triggering automatic unlinking check.")
        if not nb_hostname:
            nb_hostname = nb_name
            nb_ip = ""
        await process_delete_device(nb_id, nb_hostname, nb_name, nb_ip or "", payload)
        return {"status": "processed", "action": "filtered_out_and_unlinked"}


@app.get("/health")
def health_check() -> dict[str, str]:
    """Endpoint for checking service health."""
    return {"status": "healthy", "dry_run": str(libnms.dry_run)}


if __name__ == "__main__":
    import uvicorn
    host = webhook_config.get("host", "0.0.0.0")
    port = int(webhook_config.get("port", 8000))
    logging.info(f"Starting webhook receiver manually on {host}:{port}")
    uvicorn.run("webhook_receiver:app", host=host, port=port, reload=False)
