# streamlink-plugin-widevine

A Streamlink plugin for playing DRM-protected MPEG-DASH and HLS streams using
Google Widevine.

The plugin resolves Widevine PSSH data from the media manifest, obtains the
required content keys from a Widevine license server, and passes those keys to
third-party [dashdrm](https://github.com/titus-au/streamlink-plugin-dashdrm) /
[hlsdrm](https://github.com/titus-au/streamlink-plugin-hlsdrm) Streamlink
plugins.

## Requirements

- [Streamlink](https://streamlink.github.io/)
- A Widevine device (`.wvd`) provision
- Additional third-party Streamlink plugins:
  - [dashdrm.py](https://github.com/titus-au/streamlink-plugin-dashdrm)
  - [hlsdrm.py](https://github.com/titus-au/streamlink-plugin-hlsdrm)

## Installation

Clone the repository and use Streamlink's plugin directory option `--plugin-dir`.

Alternatively, [sideload](https://streamlink.github.io/cli/plugin-sideloading.html) 
`widevine.py`.

## Usage

The plugin accepts DASH (.mpd) and HLS (.m3u8) manifests prefixed with the 
`widevine://` scheme.

A license server must be provided. 

The plugin also requires a Widevine device.
The device can either be specified explicitly with `--widevine-device` or
placed in Streamlink's default configuration directory.

```console
streamlink \
    --plugin-dir /path/to/streamlink-plugin-widevine \
    --widevine-device /path/to/device.wvd \
    --widevine-license-server "https://license.example.com/..." \
    "widevine://https://example.com/manifest.mpd" \
    best
```

## Plugin options

The plugin accepts the following parameters:

### `license-server`

Widevine license server URL.

This parameter is required.

`--widevine-license-server "https://license.example.com/..."`

### `device`

Path to the Widevine device (`.wvd`) file.

`--widevine-device /path/to/device.wvd`

If this option is not specified, the plugin searches for a device in the
following locations:

1. `STREAMLINK_WIDEVINE_DEVICE` environment variable
2. Streamlink's default configuration directory for a file named `device.wvd`

### `pssh`

Widevine PSSH data.

Multiple PSSH strings can be supplied as a comma-separated list.

If omitted, the plugin will attempt to extract Widevine PSSH data automatically
from the media manifest and, where applicable, its initialisation segments.

`--widevine-pssh "BASE64_PSSH"`

Multiple PSSH values:

`--widevine-pssh "BASE64_PSSH_1,BASE64_PSSH_2"`

This can be useful for content which uses multiple encryption keys.

## Development

The repository contains compatibility code and a bundled version of
`pywidevine`.

No changes should be made to `widevine.py` or `pywidevine_bundled.py` 
directly as these files are generate automatically and changes will be 
overwritten.

Instead, make changes elsewhere and run the build script to generate the 
bundled implementation and the Streamlink plugin:

`python tools/build.py`

The generated `widevine.py` can then be tested with Streamlink:

```console
streamlink \
    --plugin-dir . \
    --loglevel debug \
    --widevine-license-server "https://license.example.com/..." \
    "widevine://https://example.com/manifest.mpd" \
    best
```

## Disclaimer

This project is intended for lawful use with content and services for which
you have the necessary authorisation.

Users are responsible for complying with applicable laws, license terms, and
the terms of service of the services they access.

## Third-party source code

This project incorporates and modifies code from:
- [pywidevine](https://github.com/devine-dl/pywidevine)
- [protobuf](https://github.com/protocolbuffers/protobuf)
- [construct](https://github.com/construct/construct)
- [pymp4](https://github.com/beardypig/pymp4)

See `LICENSE` and `THIRD-PARTY-NOTICES.md` for licensing and attribution 
information.
