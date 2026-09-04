from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from streamlink.compat import is_darwin, is_win32
from streamlink.exceptions import PluginError
from streamlink.logger import getLogger
from streamlink.options import Options
from streamlink.plugin import Plugin, pluginargument, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.plugin.plugin import parse_params
from streamlink.stream.dash import MPD, DASHStream
from streamlink.stream.hls import M3U8, HLSStream
from streamlink.utils.parse import parse_xml

from pywidevine_bundled import PSSH, Cdm, Device


if TYPE_CHECKING:
    from collections.abc import Iterator

    from streamlink import Streamlink
    from streamlink.stream.dash.manifest import Representation


if is_win32:
    CONFIG_DIR = (Path(os.environ.get("APPDATA") or Path.home() / "AppData")) / "streamlink"
elif is_darwin:
    CONFIG_DIR = Path.home() / "Library" / "Application Support" / "streamlink"
else:
    CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser() / "streamlink"


WIDEVINE_SCHEME_ID = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
CENC_NS = "urn:mpeg:cenc:2013"
WIDEVINE_SYSTEM_ID_BYTES = bytes.fromhex(
    "edef8ba979d64acea3c827dcd51d21ed",
)

MANIFEST_TO_PLUGIN = {
    "mpd": "dashdrm",
    "m3u8": "hlsdrm",
}

log = getLogger(__name__)


def _resolve_psshs(session: Streamlink, manifest_type: str, url: str, **kwargs) -> list[str]:
    if manifest_type == "mpd":
        return _resolve_dash_psshs(session, url, **kwargs)
    elif manifest_type == "m3u8":
        return _resolve_hls_psshs(session, url, **kwargs)
    else:
        raise PluginError("Unsupported stream type: %s", manifest_type)


def _resolve_dash_psshs(session: Streamlink, url: str, **kwargs) -> list[str]:
    manifest, mpd_params = DASHStream.fetch_manifest(session, url, **kwargs)
    mpd = MPD(
        parse_xml(manifest, ignore_ns=True),
        **mpd_params,
    )

    # PSSH from MPD
    psshs = _extract_widevine_psshs_from_mpd(mpd)
    if psshs:
        return psshs

    # PSSH from init
    log.debug("No PSSH found in DASH manifest; inspecting initialisation segments")
    psshs = []
    seen = set()
    for representation in _iter_widevine_dash_representations(mpd):
        log.debug(
            "Inspecting initialisation segment for representation %s",
            representation.id,
        )
        init = _fetch_dash_init_segment(session, representation)

        if not init:
            continue

        for pssh in _extract_widevine_psshs_from_init_segment(init):
            if pssh not in seen:
                seen.add(pssh)
                psshs.append(pssh)

    if not psshs:
        raise PluginError("Unable to resolve a Widevine PSSH from DASH manifest")

    return psshs


def _extract_widevine_psshs_from_mpd(mpd: MPD) -> list[str]:
    psshs: list[str] = []
    seen: set[str] = set()

    def extract(content_protections):
        for cp in content_protections:
            if cp.schemeIdUri != WIDEVINE_SCHEME_ID:
                continue

            pssh = cp.node.findtext(f"{{{CENC_NS}}}pssh")
            if not pssh:
                continue

            pssh = pssh.strip()

            if pssh in seen:
                continue

            seen.add(pssh)
            psshs.append(pssh)

    for period in mpd.periods:
        for adaptation_set in period.adaptationSets:
            extract(adaptation_set.contentProtections)

            for representation in adaptation_set.representations:
                extract(representation.contentProtections)

    return psshs


def _iter_widevine_dash_representations(mpd: MPD) -> Iterator[Representation]:
    for period in mpd.periods:
        for adaptation_set in period.adaptationSets:
            for representation in adaptation_set.representations:
                if any(cp.schemeIdUri == WIDEVINE_SCHEME_ID for cp in representation.contentProtections):
                    yield representation


def _fetch_dash_init_segment(session: Streamlink, representation: Representation) -> bytes | None:
    segments = representation.segments(init=True)

    try:
        segment = next(segments)
    except StopIteration:
        return None

    if not segment.init:
        return None

    headers = {}

    if segment.byterange:
        start, length = segment.byterange
        end = start + length - 1 if length else ""
        headers["Range"] = f"bytes={start}-{end}"

    return session.http.get(
        segment.uri,
        headers=headers,
    ).content


def _resolve_hls_psshs(session: Streamlink, url: str, **kwargs) -> list[str]:
    playlist = _parse_hls_playlist(session, url, **kwargs)

    if playlist.is_master:
        return _resolve_hls_master_psshs(session, playlist, **kwargs)

    return _resolve_hls_playlist_psshs(session, playlist, **kwargs)


def _parse_hls_playlist(session: Streamlink, url: str, **kwargs) -> M3U8:
    request_args = session.http.valid_request_args(**kwargs)
    res = session.http.get(url, **request_args)
    parser = HLSStream.__parser__(url)
    return parser.parse(res.text)


def _resolve_hls_master_psshs(session: Streamlink, playlist: M3U8, **kwargs) -> list[str]:
    log.debug("Inspecting HLS master playlist")

    psshs = []
    seen = set()

    for variant in playlist.playlists:
        log.debug("Inspecting variant playlist: %s", variant.uri)

        media = _parse_hls_playlist(session, variant.uri, **kwargs)

        try:
            variant_psshs = _resolve_hls_playlist_psshs(session, media, **kwargs)
            psshs.extend(pssh for pssh in variant_psshs if pssh not in seen)
            seen.update(variant_psshs)
        except PluginError:
            continue

    if not psshs:
        raise PluginError("Unable to resolve a Widevine PSSH from HLS master playlist")

    return psshs


def _resolve_hls_playlist_psshs(session: Streamlink, playlist: M3U8, **kwargs) -> list[str]:
    psshs = _extract_widevine_psshs_from_hls_playlist(playlist)
    if psshs:
        return psshs

    log.debug("No PSSH found in HLS playlist; inspecting EXT-X-MAP")

    seen_maps = set()
    seen_psshs = set()

    for segment in playlist.segments:
        if not segment.map:
            continue

        if segment.map.uri in seen_maps:
            continue

        seen_maps.add(segment.map.uri)

        log.debug("Inspecting HLS initialisation segment: %s", segment.map.uri)

        headers = {}
        if segment.map.byterange:
            start = segment.map.byterange.offset or 0
            end = start + segment.map.byterange.range - 1
            headers["Range"] = f"bytes={start}-{end}"

        data = session.http.get(
            segment.map.uri,
            headers=headers,
            **kwargs,
        ).content

        for pssh in _extract_widevine_psshs_from_init_segment(data):
            if pssh not in seen_psshs:
                seen_psshs.add(pssh)
                psshs.append(pssh)

    if not psshs:
        raise PluginError("Unable to resolve a Widevine PSSH from HLS playlist")

    return psshs


def _extract_widevine_psshs_from_hls_playlist(playlist: M3U8) -> list[str]:
    psshs = []
    seen = set()

    for segment in playlist.segments:
        key = segment.key
        if not key or not key.uri:
            continue

        if key.key_format:
            if key.key_format.lower() != WIDEVINE_SCHEME_ID.lower():
                continue

        parsed = urlsplit(key.uri)

        if parsed.scheme != "data":
            continue

        try:
            metadata, payload = parsed.path.split(",", 1)
        except ValueError:
            continue

        if ";base64" not in metadata.lower():
            continue

        try:
            data = base64.b64decode(payload, validate=True)
        except ValueError:
            continue

        pssh = base64.b64encode(data).decode("ascii")

        if pssh not in seen:
            seen.add(pssh)
            psshs.append(pssh)

    return psshs


def _extract_widevine_psshs_from_init_segment(data: bytes) -> list[str]:
    psshs = []
    seen = set()

    offset = 0

    while offset + 8 <= len(data):
        size = int.from_bytes(data[offset : offset + 4], "big")
        typ = data[offset + 4 : offset + 8]

        header = 8
        if size == 0:
            size = len(data) - offset
        elif size == 1:
            if offset + 16 > len(data):
                break
            size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header = 16

        if size < header:
            break

        if typ == b"pssh":
            body = offset + header

            if body + 20 <= offset + size:
                system_id = data[body + 4 : body + 20]

                if system_id == WIDEVINE_SYSTEM_ID_BYTES:
                    pssh = base64.b64encode(
                        data[offset : offset + size],
                    ).decode("ascii")

                    if pssh not in seen:
                        seen.add(pssh)
                        psshs.append(pssh)

        offset += size

    return psshs


def _get_json_path(path):
    def _get(value):
        for part in path:
            if isinstance(value, dict):
                try:
                    value = value[part]
                except KeyError as err:
                    raise PluginError(
                        f"JSON path key not found: {part!r}",
                    ) from err

            elif isinstance(value, list):
                try:
                    value = value[int(part)]
                except ValueError as err:
                    raise PluginError(
                        f"Expected array index, got {part!r}",
                    ) from err
                except IndexError as err:
                    raise PluginError(
                        f"Array index out of range: {part}",
                    ) from err

            else:
                raise PluginError(
                    f"Cannot access {part!r} in {type(value).__name__}",
                )

        return value

    return _get


@pluginmatcher(
    re.compile(
        r"widevine://(?P<url>\S+\.(?P<type>mpd|m3u8)(?:\?\S*)?)(?:\s(?P<params>.+))?$",
        re.IGNORECASE,
    ),
)
@pluginargument(
    "pssh",
    metavar="PSSH[,PSSH2,...]",
    type="comma_list",
    help="""
        Widevine PSSH data. Multiple PSSH strings can be supplied, comma-separated.
        If omitted, the plugin will attempt to extract PSSH data automatically.
    """,
)
@pluginargument(
    "device",
    metavar="FILEPATH",
    help="""
        Path to the Widevine device (.wvd) file.
    """,
)
@pluginargument(
    "license-url",
    required=True,
    metavar="URL",
    help="""
        Widevine license server URL.
    """,
)
@pluginargument(
    "license-header",
    metavar="KEY=VALUE",
    type="keyvalue",
    action="append",
    help="""
        A header to add to the license server HTTP request.

        Can be repeated to add multiple headers.
    """,
)
@pluginargument(
    "license-format",
    metavar="{raw,json}",
    choices=["raw", "json"],
    default="raw",
    help="""
        License server response format.
    """,
)
@pluginargument(
    "license-path",
    metavar="KEY[,KEY2,...]",
    type="comma_list",
    help="""
        Comma-separated path to the license message in a JSON response.
        Path components access object keys or array indexes depending on
        the type of the current value.
    """,
)
class Widevine(Plugin):
    def _get_device_path(self) -> Path:
        if device := self.get_option("device"):
            return Path(device)

        if env := os.getenv("STREAMLINK_WIDEVINE_DEVICE"):
            return Path(env)

        default = CONFIG_DIR / "device.wvd"
        if default.is_file():
            return default

        raise PluginError(
            "No Widevine device found. "
            "Provide a Widevine device path via plugin options, "
            "set the STREAMLINK_WIDEVINE_DEVICE environment variable, "
            f"or place device.wvd in the Streamlink config directory ({CONFIG_DIR}).",
        )

    def _get_license_message(self, response):
        license_format = self.get_option("license-format")

        if license_format is None or license_format == "raw":
            schema = validate.Schema(bytes)

        elif license_format == "json":
            license_path = self.get_option("license-path")

            if not license_path:
                raise PluginError(
                    "The license-path option is required for JSON license responses",
                )

            schema = validate.Schema(
                validate.parse_json(),
                validate.transform(_get_json_path(license_path)),
            )

        else:
            raise PluginError(
                f"Unsupported license response format: {license_format}",
            )

        return schema.validate(response.content)

    def _get_streams(self):
        data = self.match.groupdict()

        url = data["url"]
        params = parse_params(data.get("params"))
        manifest_type = data["type"].lower()

        license_url = self.get_option("license-url")
        license_header = self.get_option("license-header")

        if not license_url:
            raise PluginError("The license-url option is required")

        try:
            device = Device.load(self._get_device_path())
        except Exception as err:
            raise PluginError(f"Failed to load Widevine device: {err}") from err

        try:
            cdm = Cdm.from_device(device)
        except Exception as err:
            raise PluginError(f"Failed to initialize Widevine CDM: {err}") from err

        psshs = self.get_option("pssh")

        if psshs:
            log.debug("Using %d supplied PSSH value(s)", len(psshs))
        else:
            log.debug("Attempting to resolve Widevine PSSH")
            try:
                psshs = _resolve_psshs(
                    self.session,
                    manifest_type,
                    url,
                    **params,
                )
            except PluginError:
                raise
            except Exception as err:
                raise PluginError(f"Failed to resolve Widevine PSSH: {err}") from err

        if not psshs:
            raise PluginError("No Widevine PSSH values were found")

        try:
            session_id = cdm.open()
        except Exception as err:
            raise PluginError(f"Failed to open Widevine CDM session: {err}") from err

        try:
            decryption_keys = {}

            for index, pssh_data in enumerate(psshs, 1):
                log.debug(
                    "Processing Widevine PSSH %d/%d",
                    index,
                    len(psshs),
                )

                try:
                    pssh = PSSH(pssh_data)
                except Exception as err:
                    raise PluginError(f"Failed to parse Widevine PSSH: {err}") from err

                try:
                    challenge = cdm.get_license_challenge(
                        session_id,
                        pssh,
                    )
                except Exception as err:
                    raise PluginError(
                        f"Failed to generate Widevine license challenge: {err}",
                    ) from err

                try:
                    response = self.session.http.post(
                        license_url,
                        data=challenge,
                        headers=dict(license_header or []),
                    )
                except PluginError:
                    raise
                except Exception as err:
                    raise PluginError(
                        f"Widevine license request failed: {err}",
                    ) from err

                try:
                    license_message = self._get_license_message(response)

                    cdm.parse_license(
                        session_id,
                        license_message,
                    )
                except PluginError:
                    raise
                except Exception as err:
                    raise PluginError(
                        f"Failed to parse Widevine license response: {err}",
                    ) from err

                for key in cdm.get_keys(session_id, "CONTENT"):
                    decryption_keys[key.kid.hex] = key.key.hex()

            if not decryption_keys:
                log.warning("Widevine license server returned no content keys")

            log.debug(
                "Got %d Widevine content key(s)",
                len(decryption_keys),
            )

            drm_url = f"{MANIFEST_TO_PLUGIN[manifest_type]}://{url}"
            if params:
                drm_url += f" {params}"

            options = Options({
                "decryption-key": [f"{kid}:{key}" for kid, key in decryption_keys.items()],
            })

            return self.session.streams(
                drm_url,
                options=options,
            )
        finally:
            cdm.close(session_id)


__plugin__ = Widevine
