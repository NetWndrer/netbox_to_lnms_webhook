#!/usr/bin/env python3
"""
Simulate NetBox Webhook payloads to test webhook_receiver.py.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import requests

URL = "http://127.0.0.1:8000/webhook"
SECRET = "test_webhook_secret"  # Matches optional testing secret


def send_payload(
    event: str,
    data: dict,
    snapshots: dict | None = None,
    secret: str = "",
    corrupt_signature: bool = False,
) -> None:
    payload = {"event": event, "model": "device", "data": data}
    if snapshots:
        payload["snapshots"] = snapshots

    body_bytes = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if secret:
        signature = hmac.new(
            secret.encode("utf-8"), body_bytes, hashlib.sha512
        ).hexdigest()
        if corrupt_signature:
            signature = "corrupted" + signature[9:]
        headers["X-Hook-Signature"] = signature

    print(f"[*] Sending '{event}' event for device '{data.get('name')}' (ID: {data.get('id')})...")
    if secret:
        print(f"    HMAC Header: {headers.get('X-Hook-Signature', 'None')[:16]}...")

    try:
        response = requests.post(URL, data=body_bytes, headers=headers, timeout=5)
        print(f"    [+] Status Code: {response.status_code}")
        try:
            print(f"    [+] Response: {response.json()}")
        except ValueError:
            print(f"    [+] Response text: {response.text}")
    except requests.exceptions.ConnectionError:
        print("    [-] ERROR: Cannot connect to webhook receiver. Is it running on port 8000?")
    except Exception as e:
        print(f"    [-] ERROR: {e}")
    print("-" * 60)


def main() -> None:
    print("=" * 60)
    print("NetBox Webhook Simulator Client")
    print("=" * 60)

    # Check if receiver is online
    try:
        res = requests.get("http://127.0.0.1:8000/health", timeout=2)
        print(f"Receiver Health Status: {res.json()}")
        print("[+] Receiver is ONLINE. Running simulation tests.")
    except Exception:
        print("[-] WARNING: Webhook receiver at http://127.0.0.1:8000 is OFFLINE.")
        print("    Please run: python webhook_receiver.py")
        print("    and then run this verification script in another terminal.")
        print("=" * 60)

    # Device Mock Data
    device_active = {
        "id": 9999,
        "name": "test-router-01",
        "status": {"value": "active", "label": "Active"},
        "device_role": {"id": 1, "name": "Router", "slug": "router"},
        "device_type": {"id": 10, "model": "ios-xe", "slug": "ios-xe"},
        "tenant": {"id": 5, "name": "BOS Local Tenant", "slug": "bos-tenant"},
        "primary_ip4": {
            "id": 1234,
            "address": "192.168.100.1/24",
            "dns_name": "test-router-01.bos.local",
        },
        "oob_ip": None,
    }

    device_offline = {
        "id": 8888,
        "name": "test-switch-offline",
        "status": {"value": "offline", "label": "Offline"},  # Excluded by default status filter
        "device_role": {"id": 2, "name": "Switch", "slug": "switch"},
        "device_type": {"id": 11, "model": "nx-os", "slug": "nx-os"},
        "tenant": None,
        "primary_ip4": {
            "id": 1235,
            "address": "192.168.100.2/24",
            "dns_name": "test-switch-offline.bos.local",
        },
    }

    # Test Case 1: Bad Signature (Unauthorised verification)
    print("\n[Test 1] Testing HMAC signature verification with corrupted signature...")
    send_payload("created", device_active, secret=SECRET, corrupt_signature=True)

    # Test Case 2: Active device enrollment / update
    print("\n[Test 2] Testing payload signature validation with correct signature and active device (creates/updates)...")
    send_payload("created", device_active, secret=SECRET)

    # Test Case 3: Filtered out device (Offline status)
    print("\n[Test 3] Testing device which does not match active status filters (should ignore/unlink)...")
    send_payload("created", device_offline, secret=SECRET)

    # Test Case 4: Device renamed (rename detection via pre/post snapshot)
    print("\n[Test 4] Testing rename detection update...")
    renamed_device = device_active.copy()
    renamed_device["name"] = "test-router-01-new"
    snapshots = {
        "pre": {
            "id": 9999,
            "name": "test-router-01",
            "primary_ip4": {"address": "192.168.100.1/24", "dns_name": "test-router-01.bos.local"},
        },
        "post": renamed_device,
    }
    send_payload("updated", renamed_device, snapshots=snapshots, secret=SECRET)

    # Test Case 5: Device deleted / decommissioned
    print("\n[Test 5] Testing device unlinking upon NetBox model deletion...")
    send_payload("deleted", device_active, secret=SECRET)


if __name__ == "__main__":
    main()
