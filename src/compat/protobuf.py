"""
Minimal protobuf compatibility required by the bundled pywidevine implementation.

This is intentionally not a general-purpose protobuf implementation.

Protocol Buffers - Google's data interchange format
Copyright 2008 Google Inc.  All rights reserved.

Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file or at
https://developers.google.com/open-source/licenses/bsd
"""

_BOOL = 1
_INT32 = 2
_INT64 = 3
_UINT32 = 4
_BYTES = 5
_STRING = 6
_ENUM = 7
_MESSAGE = 8


class DecodeError(Exception):
    """Exception raised when deserializing messages."""


class _ProtoEnum:
    _values = {}

    @classmethod
    def Value(cls, name):
        try:
            return cls._values[name]
        except KeyError:
            raise ValueError(
                f"Enum {cls.__name__} has no value defined for name {name!r}",
            ) from None

    @classmethod
    def Name(cls, value):
        for name, number in cls._values.items():
            if number == value:
                return name

        raise ValueError(
            f"Enum {cls.__name__} has no value defined for value {value!r}",
        )

    @classmethod
    def keys(cls):
        return list(cls._values.keys())


class _Field:
    def __init__(
        self,
        number,
        type_,
        *,
        repeated=False,
        default=None,
        enum=None,
        message=None,
    ):
        self.number = number
        self.type = type_
        self.repeated = repeated
        self.default = default
        self.enum = enum
        self.message = message
        self.name = None


class _FieldDescriptor:
    def __init__(self, name):
        self.name = name


class _Repeated(list):
    def __init__(self, values=(), *, field=None, changed=None):
        super().__init__()
        self._field = field
        self._changed = changed

        for value in values:
            self._prepare(value)
            list.append(self, value)

    def _prepare(self, value):
        if self._field is not None and self._field.type == _MESSAGE:
            value._parent_changed = self._mark_changed

        return value

    def _mark_changed(self):
        if self._changed is not None:
            self._changed()

    def append(self, value):
        super().append(self._prepare(value))
        self._mark_changed()

    def extend(self, values):
        super().extend(self._prepare(value) for value in values)
        self._mark_changed()

    def insert(self, index, value):
        super().insert(index, self._prepare(value))
        self._mark_changed()

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            value = [self._prepare(item) for item in value]
        else:
            value = self._prepare(value)

        super().__setitem__(key, value)
        self._mark_changed()

    def __delitem__(self, key):
        super().__delitem__(key)
        self._mark_changed()

    def pop(self, index=-1):
        value = super().pop(index)
        self._mark_changed()
        return value

    def remove(self, value):
        super().remove(value)
        self._mark_changed()

    def clear(self):
        super().clear()
        self._mark_changed()


class _Message:
    _fields = {}

    def __init_subclass__(cls):
        cls._fields_by_number = {}

        for name, field in cls._fields.items():
            field.name = name
            cls._fields_by_number[field.number] = field

    def __init__(self, **kwargs):
        object.__setattr__(self, "_values", {})
        object.__setattr__(self, "_parent_changed", None)
        object.__setattr__(self, "_composites", {})
        object.__setattr__(self, "_unknown_fields", [])
        object.__setattr__(self, "_serialized", None)

        for name, value in kwargs.items():
            if name not in self._fields:
                raise ValueError(
                    f"Protocol message {type(self).__name__} has no {name!r} field.",
                )

            if value is None:
                continue

            field = self._fields[name]

            if field.type == _ENUM and isinstance(value, str):
                value = field.enum.Value(value)

            self._values[name] = value

    def __getattr__(self, name):
        field = self._fields.get(name)

        if field is None:
            raise AttributeError(name)

        if name in self._values:
            return self._values[name]

        if field.repeated:
            value = _Repeated(
                field=field,
                changed=self._mark_changed,
            )
            self._values[name] = value
            return value

        if field.default is not None:
            return field.default

        if field.type == _BOOL:
            return False

        if field.type in (_INT32, _INT64, _UINT32, _ENUM):
            return 0

        if field.type == _BYTES:
            return b""

        if field.type == _STRING:
            return ""

        if field.type == _MESSAGE:
            if name not in self._composites:
                value = field.message()

                def changed():
                    self._values[name] = value
                    self._mark_changed()

                value._parent_changed = changed
                self._composites[name] = value

            return self._composites[name]

        raise AttributeError(name)

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return

        field = self._fields.get(name)

        if field is None:
            raise AttributeError(
                f"Protocol message {type(self).__name__} has no {name!r} field.",
            )

        if field.type == _MESSAGE:
            raise AttributeError(
                f"Assignment not allowed to message field {name!r}.",
            )

        self._values[name] = value

        self._mark_changed()

    def _mark_changed(self):
        self._serialized = None

        if self._parent_changed is not None:
            self._parent_changed()

    def HasField(self, name):
        field = self._fields.get(name)

        if field is None:
            raise ValueError(
                f"Protocol message {type(self).__name__} has no {name!r} field.",
            )

        if field.repeated:
            raise ValueError(
                f"Protocol message {type(self).__name__} has no singular {name!r} field.",
            )

        return name in self._values

    def CopyFrom(self, other):
        if type(self) is not type(other):
            raise TypeError(
                "Parameter to CopyFrom() must be instance of same class: "
                f"expected {type(self).__name__} got {type(other).__name__}.",
            )

        self._values = dict(other._values)

        self._mark_changed()

    def SerializeToString(self):
        if self._serialized is not None:
            return self._serialized

        result = bytearray()

        for name, field in self._fields.items():
            if name not in self._values:
                continue

            value = self._values[name]

            if field.repeated:
                for item in value:
                    result.extend(_encode_field(field, item))
            else:
                result.extend(_encode_field(field, value))

        for raw in self._unknown_fields:
            result.extend(raw)

        return bytes(result)

    def ParseFromString(self, data):
        offset = 0

        while offset < len(data):
            field_start = offset

            key, offset = _decode_varint(data, offset)
            field_number, wire_type = _decode_key(key)

            field = self._fields_by_number.get(field_number)

            if field is None:
                offset = _skip_field(data, offset, wire_type)
                self._unknown_fields.append(data[field_start:offset])
                continue

            if wire_type == 0:
                value, offset = _decode_varint(data, offset)
                value = _decode_field_varint(field, value)

            elif wire_type == 2:
                value, offset = _decode_length_delimited(data, offset)
                value = _decode_field_length_delimited(field, value)

            else:
                raise DecodeError(
                    f"Unsupported wire type {wire_type} for field {field.name!r}.",
                )

            if field.repeated:
                values = self._values.get(field.name)

                if values is None:
                    values = _Repeated(
                        field=field,
                        changed=self._mark_changed,
                    )
                    self._values[field.name] = values

                list.append(values, values._prepare(value))

            else:
                self._values[field.name] = value

                if field.type == _MESSAGE:

                    def changed(
                        name=field.name,
                        value=value,
                    ):
                        self._values[name] = value
                        self._mark_changed()

                    value._parent_changed = changed
                    self._composites[field.name] = value

        self._serialized = bytes(data)
        return len(data)

    def ListFields(self):
        result = []

        fields = sorted(
            self._fields.items(),
            key=lambda item: item[1].number,
        )

        for name, _field in fields:
            if name not in self._values:
                continue

            result.append(
                (_FieldDescriptor(name), self._values[name]),
            )

        return result


def _encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1

    result = bytearray()

    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7

    result.append(value)

    return bytes(result)


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0

    while offset < len(data):
        byte = data[offset]
        offset += 1

        value |= (byte & 0x7F) << shift

        if not byte & 0x80:
            return value, offset

        shift += 7

        if shift >= 70:
            raise DecodeError("Too many bytes when decoding varint.")

    raise DecodeError("Truncated varint.")


def _encode_key(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _decode_key(value: int) -> tuple[int, int]:
    return value >> 3, value & 0x07


def _encode_length_delimited(value: bytes) -> bytes:
    return _encode_varint(len(value)) + value


def _decode_length_delimited(
    data: bytes,
    offset: int,
) -> tuple[bytes, int]:
    length, offset = _decode_varint(data, offset)
    end = offset + length

    if end > len(data):
        raise DecodeError("Truncated length-delimited field.")

    return data[offset:end], end


def _encode_field(field, value):
    if field.type == _BOOL:
        return _encode_key(field.number, 0) + _encode_varint(int(value))

    if field.type in (_INT32, _INT64, _UINT32):
        return _encode_key(field.number, 0) + _encode_varint(value)

    if field.type == _ENUM:
        if isinstance(value, str):
            value = field.enum.Value(value)

        return _encode_key(field.number, 0) + _encode_varint(value)

    if field.type == _BYTES:
        return _encode_key(field.number, 2) + _encode_length_delimited(value)

    if field.type == _STRING:
        return _encode_key(field.number, 2) + _encode_length_delimited(value.encode("utf-8"))

    if field.type == _MESSAGE:
        return _encode_key(field.number, 2) + _encode_length_delimited(value.SerializeToString())

    raise NotImplementedError(
        f"Encoding field type {field.type!r} is not implemented.",
    )


def _decode_field_varint(field, value):
    if field.type == _BOOL:
        return bool(value)

    if field.type == _UINT32:
        return value & 0xFFFFFFFF

    if field.type == _INT32:
        value &= 0xFFFFFFFF
        if value & 0x80000000:
            value -= 1 << 32
        return value

    if field.type == _INT64:
        value &= 0xFFFFFFFFFFFFFFFF
        if value & 0x8000000000000000:
            value -= 1 << 64
        return value

    if field.type == _ENUM:
        return value

    raise DecodeError(
        f"Cannot decode field type {field.type!r} as a varint.",
    )


def _decode_field_length_delimited(field, value):
    if field.type == _BYTES:
        return value

    if field.type == _STRING:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecodeError(
                f"Invalid UTF-8 in field {field.name!r}.",
            ) from exc

    if field.type == _MESSAGE:
        message = field.message()
        message.ParseFromString(value)
        return message

    raise DecodeError(
        f"Cannot decode field type {field.type!r} as length-delimited.",
    )


def _skip_field(data, offset, wire_type):
    if wire_type == 0:
        _, offset = _decode_varint(data, offset)
        return offset

    if wire_type == 1:
        end = offset + 8

        if end > len(data):
            raise DecodeError("Truncated 64-bit field.")

        return end

    if wire_type == 2:
        _, offset = _decode_length_delimited(data, offset)
        return offset

    if wire_type == 5:
        end = offset + 4

        if end > len(data):
            raise DecodeError("Truncated 32-bit field.")

        return end

    raise DecodeError(
        f"Unsupported wire type {wire_type}.",
    )
