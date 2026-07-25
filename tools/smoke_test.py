import os
from pathlib import Path

import requests

from pywidevine_bundled import PSSH, Cdm, Device


WVD = Path(os.environ["STREAMLINK_WIDEVINE_DEVICE"])

PSSH_DATA = (
    "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa"
    "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="
)

LICENSE_URL = "https://cwip-shaka-proxy.appspot.com/no_auth"


def main() -> None:
    print("Loading PSSH...")
    pssh = PSSH(PSSH_DATA)

    print(f"Loading device: {WVD}")
    device = Device.load(WVD)

    print("Creating CDM...")
    cdm = Cdm.from_device(device)

    print("Opening session...")
    session_id = cdm.open()

    try:
        print("Generating licence challenge...")
        challenge = cdm.get_license_challenge(session_id, pssh)

        print("Requesting test licence...")
        response = requests.post(
            LICENSE_URL,
            data=challenge,
            timeout=30,
        )
        response.raise_for_status()

        print("Parsing licence...")
        cdm.parse_license(session_id, response.content)

        print("Keys:")
        for key in cdm.get_keys(session_id):
            print(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")

    finally:
        print("Closing session...")
        cdm.close(session_id)


if __name__ == "__main__":
    main()
