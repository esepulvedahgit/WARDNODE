#!/usr/bin/env python3
"""
Download MaxMind GeoLite2-Country database manually.

Usage:
    python scripts/download_geoip.py

Requires MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in your .env or environment.
Free registration at: https://www.maxmind.com/en/geolite2/signup

This script is for manual/emergency use. In production, the `geoipupdate`
Docker service handles downloads and weekly updates automatically.

After running this script, restart the console to pick up the new DB:
    docker compose restart console
"""
import base64
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

DEST_DIR = Path(__file__).parent.parent / "data" / "geoip"
DEST_FILE = DEST_DIR / "GeoLite2-Country.mmdb"
DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"


def main() -> None:
    account_id = os.getenv("MAXMIND_ACCOUNT_ID", "").strip()
    license_key = os.getenv("MAXMIND_LICENSE_KEY", "").strip()

    if not account_id or not license_key:
        # Try loading from .env file in project root
        env_file = Path(__file__).parent.parent / ".env"
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("MAXMIND_ACCOUNT_ID="):
                    account_id = line.split("=", 1)[1].strip()
                elif line.startswith("MAXMIND_LICENSE_KEY="):
                    license_key = line.split("=", 1)[1].strip()

    if not account_id or not license_key:
        print("Error: MAXMIND_ACCOUNT_ID y MAXMIND_LICENSE_KEY no configurados.", file=sys.stderr)
        print("Agregalos en tu .env o como variables de entorno.", file=sys.stderr)
        sys.exit(1)

    DEST_DIR.mkdir(parents=True, exist_ok=True)
    credentials = base64.b64encode(f"{account_id}:{license_key}".encode()).decode()
    tar_path = DEST_DIR / "GeoLite2-Country.tar.gz"

    print(f"Descargando GeoLite2-Country desde MaxMind...")
    try:
        req = urllib.request.Request(DOWNLOAD_URL, headers={"Authorization": f"Basic {credentials}"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk = 65536
            with open(tar_path, "wb") as f:
                while True:
                    data = resp.read(chunk)
                    if not data:
                        break
                    f.write(data)
                    downloaded += len(data)
                    if total:
                        pct = downloaded * 100 // total
                        print(f"\r  {pct}%  {downloaded // 1024} KB / {total // 1024} KB", end="", flush=True)
        print()
    except urllib.error.HTTPError as exc:
        print(f"\nError HTTP {exc.code}: {exc.reason}", file=sys.stderr)
        if exc.code == 401:
            print("Credenciales incorrectas. Verifica MAXMIND_ACCOUNT_ID y MAXMIND_LICENSE_KEY.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)

    print("Extrayendo .mmdb...")
    try:
        with tarfile.open(tar_path) as tf:
            mmdb_member = next(m for m in tf.getmembers() if m.name.endswith(".mmdb"))
            with tf.extractfile(mmdb_member) as src:
                DEST_FILE.write_bytes(src.read())
        tar_path.unlink()
    except Exception as exc:
        print(f"Error al extraer: {exc}", file=sys.stderr)
        sys.exit(1)

    size_mb = DEST_FILE.stat().st_size / 1_048_576
    print(f"Listo: {DEST_FILE}  ({size_mb:.1f} MB)")
    print()
    print("Próximo paso:")
    print("  docker compose restart console   (aplica la nueva DB automáticamente)")


if __name__ == "__main__":
    main()
