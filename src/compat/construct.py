"""
Minimal construct compatibility required by the bundled pywidevine implementation.

This is intentionally not a general-purpose construct implementation.
"""

import struct


_DEVICE_TYPES = {
    1: "CHROME",
    2: "ANDROID",
}


class ConstructError(Exception):
    pass


class Container(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


class _Struct:
    def __init__(self, version=None):
        self.version = version

    def parse(self, data):
        try:
            if data[:3] != b"WVD":
                raise ConstructError("invalid signature")

            version = data[3]

            if self.version is None:
                return Container(version=version)

            if version != self.version:
                raise ConstructError("invalid version")

            type_, security_level = data[4:6]

            private_key_len = struct.unpack_from(">H", data, 7)[0]
            offset = 9
            private_key = data[offset : offset + private_key_len]
            offset += private_key_len

            client_id_len = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            client_id = data[offset : offset + client_id_len]
            offset += client_id_len

            result = Container(
                version=version,
                type_=_DEVICE_TYPES[type_],
                security_level=security_level,
                flags={},
                private_key=private_key,
                client_id=client_id,
            )

            if version == 1:
                vmp_len = struct.unpack_from(">H", data, offset)[0]
                offset += 2
                result.vmp = data[offset : offset + vmp_len]

            return result

        except (IndexError, KeyError, struct.error) as e:
            raise ConstructError(str(e)) from e

    def parse_stream(self, stream):
        return self.parse(stream.read())

    def build(self, obj):
        private_key = obj["private_key"]
        client_id = obj["client_id"]
        type_ = obj["type_"]

        if isinstance(type_, str):
            type_ = {name: value for value, name in _DEVICE_TYPES.items()}[type_]
        elif hasattr(type_, "value"):
            type_ = type_.value

        return (
            b"WVD"
            + bytes((2, type_, obj["security_level"], 0))
            + struct.pack(">H", len(private_key))
            + private_key
            + struct.pack(">H", len(client_id))
            + client_id
        )


class _Structures:
    header = _Struct()
    v1 = _Struct(1)
    v2 = _Struct(2)
