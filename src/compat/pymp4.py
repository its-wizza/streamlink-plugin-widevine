"""
Minimal pymp4 compatibility required by the bundled pywidevine implementation.

This is intentionally not a general-purpose pymp4 implementation.

Copyright 2016 beardypig

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import struct
from uuid import UUID

from .construct import Container


class Box:
    @staticmethod
    def parse(data):
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {data!r}")

        if len(data) < 32:
            raise OSError("PSSH box is too small")

        size, type_ = struct.unpack_from(">I4s", data)

        if size == 1:
            if len(data) < 40:
                raise OSError("PSSH box is too small")

            size = struct.unpack_from(">Q", data, 8)[0]
            offset = 16
        else:
            offset = 8

        if type_ != b"pssh":
            raise OSError("Not a PSSH box")

        if size != len(data):
            raise OSError("Invalid PSSH box size")

        version = data[offset]
        flags = int.from_bytes(data[offset + 1 : offset + 4], "big")
        offset += 4

        if flags != 0:
            raise ValueError("PSSH flags must be 0")

        if version not in (0, 1):
            raise OSError(f"Unsupported PSSH version {version}")

        if offset + 16 > len(data):
            raise OSError("Truncated PSSH system ID")

        system_id = UUID(bytes=data[offset : offset + 16])
        offset += 16

        key_ids = None

        if version == 1:
            if offset + 4 > len(data):
                raise OSError("Truncated PSSH KID count")

            key_id_count = struct.unpack_from(">I", data, offset)[0]
            offset += 4

            required = key_id_count * 16

            if offset + required > len(data):
                raise OSError("Truncated PSSH KIDs")

            key_ids = []

            for _ in range(key_id_count):
                key_ids.append(UUID(bytes=data[offset : offset + 16]))
                offset += 16

        if offset + 4 > len(data):
            raise OSError("Truncated PSSH data size")

        init_data_size = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        if offset + init_data_size != len(data):
            raise OSError("Invalid PSSH data size")

        init_data = data[offset : offset + init_data_size]

        return Container(
            type=type_,
            version=version,
            flags=flags,
            system_ID=system_id,
            key_IDs=key_ids,
            init_data=init_data,
        )

    @staticmethod
    def build(obj):
        type_ = obj["type"]

        if type_ != b"pssh":
            raise ValueError("Only PSSH boxes are supported")

        version = obj.get("version", 0)
        flags = obj.get("flags", 0)
        system_id = obj["system_ID"]
        key_ids = obj.get("key_IDs")
        init_data = obj.get("init_data", b"")

        if version not in (0, 1):
            raise ValueError(f"Unsupported PSSH version {version}")

        if flags != 0:
            raise ValueError("PSSH flags must be 0")

        if version == 1 and not key_ids:
            version = 0

        if not isinstance(system_id, UUID):
            system_id = UUID(str(system_id))

        body = bytes((version,)) + flags.to_bytes(3, "big") + system_id.bytes

        if version == 1:
            key_ids = key_ids or []

            body += struct.pack(">I", len(key_ids))

            for key_id in key_ids:
                if not isinstance(key_id, UUID):
                    key_id = UUID(str(key_id))

                body += key_id.bytes

        body += struct.pack(">I", len(init_data))
        body += init_data

        size = 8 + len(body)

        return struct.pack(">I4s", size, b"pssh") + body
