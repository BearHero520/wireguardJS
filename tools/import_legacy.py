"""Import the original embedded bundle without executing its contents."""
import base64
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    original = ROOT / "wireguard.js"
    backup = ROOT / ".local" / "wireguard.original.js"
    if backup.exists():
        raise SystemExit("Original backup already exists; import skipped.")
    source = original.read_bytes()
    match = re.search(rb'z="([A-Za-z0-9+/=]{1000,})"', source)
    if not match:
        raise SystemExit("No legacy embedded package found.")
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(source)
    allowed = {"service.sh", "wg0.conf", "scripts/run.sh", "bin/wg"}
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(match[1])), mode="r:gz") as archive:
        for member in archive.getmembers():
            relative = member.name.removeprefix("plugin_resources/")
            if not member.isfile() or relative not in allowed:
                continue
            data = archive.extractfile(member).read()
            if relative.endswith((".sh", ".conf")):
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = data.decode("gb18030")
                data = text.replace("\r\n", "\n").encode("utf-8")
            target = ROOT / "resources" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            print("Imported", relative)


if __name__ == "__main__":
    main()
