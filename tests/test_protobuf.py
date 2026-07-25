import pytest
import pywidevine.license_protocol_pb2 as upstream_protocol
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.internal.enum_type_wrapper import EnumTypeWrapper

from compat import license_protocol as compat
from compat.protobuf import (
    _BOOL,
    _BYTES,
    _ENUM,
    _INT32,
    _INT64,
    _MESSAGE,
    _STRING,
    _UINT32,
    DecodeError,
    _decode_key,
    _decode_length_delimited,
    _decode_varint,
    _encode_key,
    _encode_length_delimited,
    _encode_varint,
    _Field,
    _Message,
    _ProtoEnum,
)


class ExampleEnum(_ProtoEnum):
    _values = {
        "UNKNOWN": 0,
        "FIRST": 1,
        "SECOND": 2,
    }


class ExampleChild(_Message):
    _fields = {
        "value": _Field(1, _UINT32),
    }


class ExampleMessage(_Message):
    _fields = {
        "enabled": _Field(1, _BOOL),
        "count": _Field(2, _UINT32),
        "data": _Field(3, _BYTES),
        "name": _Field(4, _STRING),
        "values": _Field(5, _UINT32, repeated=True),
        "child": _Field(6, _MESSAGE, message=ExampleChild),
        "mode": _Field(7, _ENUM, enum=ExampleEnum),
        "signed32": _Field(8, _INT32),
        "signed64": _Field(9, _INT64),
        "blobs": _Field(10, _BYTES, repeated=True),
        "children": _Field(11, _MESSAGE, repeated=True, message=ExampleChild),
    }


def make_message(field_type):
    file = descriptor_pb2.FileDescriptorProto()
    file.name = "test.proto"

    message = file.message_type.add()
    message.name = "TestMessage"

    field = message.field.add()
    field.name = "value"
    field.number = 1
    field.label = field.LABEL_OPTIONAL
    field.type = field_type

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)

    descriptor = pool.FindMessageTypeByName("TestMessage")

    return message_factory.GetMessageClass(descriptor)


def make_enum():
    file = descriptor_pb2.FileDescriptorProto()
    file.name = "enum_test.proto"

    enum = file.enum_type.add()
    enum.name = "ExampleEnum"

    for name, number in (
        ("UNKNOWN", 0),
        ("FIRST", 1),
        ("SECOND", 2),
    ):
        value = enum.value.add()
        value.name = name
        value.number = number

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)

    return EnumTypeWrapper(
        pool.FindEnumTypeByName("ExampleEnum"),
    )


def make_example_message():
    file = descriptor_pb2.FileDescriptorProto()
    file.name = "example_message.proto"
    file.syntax = "proto2"

    message = file.message_type.add()
    message.name = "ExampleMessage"

    child = message.nested_type.add()
    child.name = "Child"

    field = child.field.add()
    field.name = "value"
    field.number = 1
    field.label = field.LABEL_OPTIONAL
    field.type = field.TYPE_UINT32

    enum = message.enum_type.add()
    enum.name = "Mode"

    for name, number in (
        ("UNKNOWN", 0),
        ("FIRST", 1),
        ("SECOND", 2),
    ):
        value = enum.value.add()
        value.name = name
        value.number = number

    fields = [
        ("enabled", 1, descriptor_pb2.FieldDescriptorProto.TYPE_BOOL, False),
        ("count", 2, descriptor_pb2.FieldDescriptorProto.TYPE_UINT32, False),
        ("data", 3, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES, False),
        ("name", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING, False),
        ("values", 5, descriptor_pb2.FieldDescriptorProto.TYPE_UINT32, True),
        ("signed32", 8, descriptor_pb2.FieldDescriptorProto.TYPE_INT32, False),
        ("signed64", 9, descriptor_pb2.FieldDescriptorProto.TYPE_INT64, False),
        ("blobs", 10, descriptor_pb2.FieldDescriptorProto.TYPE_BYTES, True),
    ]

    for name, number, type_, repeated in fields:
        field = message.field.add()
        field.name = name
        field.number = number
        field.label = field.LABEL_REPEATED if repeated else field.LABEL_OPTIONAL
        field.type = type_

    field = message.field.add()
    field.name = "child"
    field.number = 6
    field.label = field.LABEL_OPTIONAL
    field.type = field.TYPE_MESSAGE
    field.type_name = ".ExampleMessage.Child"

    field = message.field.add()
    field.name = "mode"
    field.number = 7
    field.label = field.LABEL_OPTIONAL
    field.type = field.TYPE_ENUM
    field.type_name = ".ExampleMessage.Mode"

    field = message.field.add()
    field.name = "children"
    field.number = 11
    field.label = field.LABEL_REPEATED
    field.type = field.TYPE_MESSAGE
    field.type_name = ".ExampleMessage.Child"

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)

    descriptor = pool.FindMessageTypeByName("ExampleMessage")

    return message_factory.GetMessageClass(descriptor)


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        2,
        127,
        128,
        255,
        300,
        16383,
        16384,
        0xFFFFFFFF,
    ],
)
def test_uint32_encoding(value):
    Message = make_message(
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT32,
    )

    expected = Message(value=value).SerializeToString()

    assert expected == _encode_key(1, 0) + _encode_varint(value)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"\x00",
        b"hello",
        bytes(range(256)),
    ],
)
def test_bytes_encoding(value):
    Message = make_message(
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES,
    )

    expected = Message(value=value).SerializeToString()

    assert expected == _encode_key(1, 2) + _encode_length_delimited(value)


@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        127,
        128,
        300,
        16384,
        0xFFFFFFFF,
    ],
)
def test_uint32_decoding(value):
    Message = make_message(
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT32,
    )

    data = Message(value=value).SerializeToString()

    key, offset = _decode_varint(data, 0)
    field_number, wire_type = _decode_key(key)

    assert field_number == 1
    assert wire_type == 0

    decoded, offset = _decode_varint(data, offset)

    assert decoded == value
    assert offset == len(data)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"hello",
        bytes(range(256)),
    ],
)
def test_bytes_decoding(value):
    Message = make_message(
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES,
    )

    data = Message(value=value).SerializeToString()

    key, offset = _decode_varint(data, 0)
    field_number, wire_type = _decode_key(key)

    assert field_number == 1
    assert wire_type == 2

    decoded, offset = _decode_length_delimited(data, offset)

    assert decoded == value
    assert offset == len(data)


def test_truncated_varint():
    with pytest.raises(DecodeError):
        _decode_varint(b"\x80", 0)


def test_overlong_varint():
    with pytest.raises(DecodeError):
        _decode_varint(b"\x80" * 10 + b"\x00", 0)


def test_truncated_length_delimited():
    # Claims to contain 5 bytes, but only contains 3.
    data = b"\x05abc"

    with pytest.raises(DecodeError):
        _decode_length_delimited(data, 0)


def test_decode_varint_offset():
    data = b"xxx" + _encode_varint(300) + b"yyy"

    value, offset = _decode_varint(data, 3)

    assert value == 300
    assert offset == 5


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("UNKNOWN", 0),
        ("FIRST", 1),
        ("SECOND", 2),
    ],
)
def test_enum_value(name, value):
    google = make_enum()

    assert ExampleEnum.Value(name) == google.Value(name) == value


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (0, "UNKNOWN"),
        (1, "FIRST"),
        (2, "SECOND"),
    ],
)
def test_enum_name(value, name):
    google = make_enum()

    assert ExampleEnum.Name(value) == google.Name(value) == name


def test_enum_keys():
    google = make_enum()

    assert ExampleEnum.keys() == google.keys()


def test_enum_invalid_name():
    google = make_enum()

    with pytest.raises(ValueError):
        google.Value("INVALID")

    with pytest.raises(ValueError):
        ExampleEnum.Value("INVALID")


def test_enum_invalid_value():
    google = make_enum()

    with pytest.raises(ValueError):
        google.Name(999)

    with pytest.raises(ValueError):
        ExampleEnum.Name(999)


def test_license_type():
    assert compat.LicenseType.keys() == upstream_protocol.LicenseType.keys()

    for name in upstream_protocol.LicenseType.keys():
        assert compat.LicenseType.Value(name) == upstream_protocol.LicenseType.Value(name)

        value = upstream_protocol.LicenseType.Value(name)

        assert compat.LicenseType.Name(value) == upstream_protocol.LicenseType.Name(value)


def test_key_type():
    custom = compat.License.KeyContainer.KeyType
    google = upstream_protocol.License.KeyContainer.KeyType

    assert custom.keys() == google.keys()

    for name in google.keys():
        assert custom.Value(name) == google.Value(name)

        value = google.Value(name)

        assert custom.Name(value) == google.Name(value)


def test_message_constructor():
    message = ExampleMessage(
        enabled=True,
        count=42,
        data=b"hello",
        name="test",
    )

    assert message.enabled is True
    assert message.count == 42
    assert message.data == b"hello"
    assert message.name == "test"


def test_message_defaults():
    message = ExampleMessage()

    assert message.enabled is False
    assert message.count == 0
    assert message.data == b""
    assert message.name == ""


def test_message_repeated():
    class RepeatedMessage(_Message):
        _fields = {
            "values": _Field(
                1,
                _UINT32,
                repeated=True,
            ),
        }

    message = RepeatedMessage()

    assert message.values == []

    message.values.append(123)

    assert message.values == [123]


def test_message_assignment():
    message = ExampleMessage()

    message.enabled = True
    message.count = 42
    message.data = b"hello"
    message.name = "test"

    assert message.enabled is True
    assert message.count == 42
    assert message.data == b"hello"
    assert message.name == "test"


def test_message_unknown_field_assignment():
    message = ExampleMessage()

    with pytest.raises(AttributeError):
        message.does_not_exist = 123


def test_message_defaults_match_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    assert custom.enabled == google.enabled
    assert custom.count == google.count
    assert custom.data == google.data
    assert custom.name == google.name


def test_message_constructor_matches_google():
    GoogleMessage = make_example_message()

    values = {
        "enabled": True,
        "count": 42,
        "data": b"hello",
        "name": "test",
    }

    custom = ExampleMessage(**values)
    google = GoogleMessage(**values)

    assert custom.enabled == google.enabled
    assert custom.count == google.count
    assert custom.data == google.data
    assert custom.name == google.name


def test_message_assignment_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    custom.enabled = google.enabled = True
    custom.count = google.count = 42
    custom.data = google.data = b"hello"
    custom.name = google.name = "test"

    assert custom.enabled == google.enabled
    assert custom.count == google.count
    assert custom.data == google.data
    assert custom.name == google.name


def test_message_presence_storage():
    message = ExampleMessage()

    assert "count" not in message._values
    assert message.count == 0
    assert "count" not in message._values

    message.count = 0

    assert message.count == 0
    assert "count" in message._values


def test_message_has_field_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    for name in ("enabled", "count", "data", "name"):
        assert custom.HasField(name) == google.HasField(name)
        assert custom.HasField(name) is False

    custom.count = 0
    google.count = 0

    assert custom.HasField("count") == google.HasField("count")
    assert custom.HasField("count") is True

    custom.data = b""
    google.data = b""

    assert custom.HasField("data") == google.HasField("data")
    assert custom.HasField("data") is True


def test_message_has_field_unknown():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    with pytest.raises(ValueError):
        google.HasField("does_not_exist")

    with pytest.raises(ValueError):
        custom.HasField("does_not_exist")


def test_message_repeated_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    assert list(custom.values) == list(google.values) == []

    custom.values.append(1)
    custom.values.append(2)

    google.values.append(1)
    google.values.append(2)

    assert list(custom.values) == list(google.values) == [1, 2]


def test_message_has_field_repeated():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    with pytest.raises(ValueError):
        google.HasField("values")

    with pytest.raises(ValueError):
        custom.HasField("values")


def test_nested_message_access_presence_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage()

    assert google.HasField("child") is False

    child = google.child

    assert child.value == 0
    assert google.HasField("child") is False

    child.value = 42

    assert google.HasField("child") is True


def test_nested_message_access_presence():
    message = ExampleMessage()

    assert message.HasField("child") is False

    child = message.child

    assert child.value == 0
    assert message.HasField("child") is False

    child.value = 42

    assert message.HasField("child") is True


def test_nested_message_constructor_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        child=ExampleChild(value=42),
    )
    google = GoogleMessage(
        child={"value": 42},
    )

    assert custom.HasField("child") == google.HasField("child")
    assert custom.HasField("child") is True
    assert custom.child.value == google.child.value == 42


def test_nested_message_direct_assignment_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage()

    with pytest.raises(AttributeError):
        google.child = GoogleMessage.Child(value=42)


def test_nested_message_copy_from():
    message = ExampleMessage()

    assert message.HasField("child") is False

    message.child.CopyFrom(
        ExampleChild(value=42),
    )

    assert message.HasField("child") is True
    assert message.child.value == 42


def test_nested_message_direct_assignment():
    message = ExampleMessage()

    with pytest.raises(AttributeError):
        message.child = ExampleChild(value=42)


def test_nested_message_constructor_presence():
    child = ExampleChild(value=42)

    message = ExampleMessage(child=child)

    assert message.HasField("child") is True
    assert message.child.value == 42


def test_message_serialization_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        enabled=True,
        count=42,
        data=b"hello",
        name="test",
    )

    google = GoogleMessage(
        enabled=True,
        count=42,
        data=b"hello",
        name="test",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_empty_matches_google():
    GoogleMessage = make_example_message()

    assert ExampleMessage().SerializeToString() == GoogleMessage().SerializeToString() == b""


def test_message_serialization_explicit_defaults_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        enabled=False,
        count=0,
        data=b"",
        name="",
    )

    google = GoogleMessage(
        enabled=False,
        count=0,
        data=b"",
        name="",
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_repeated_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    custom.values.extend([1, 2, 127, 128, 300])
    google.values.extend([1, 2, 127, 128, 300])

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_enum_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(mode=2)
    google = GoogleMessage(mode=2)

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_enum_name_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(mode="SECOND")
    google = GoogleMessage(mode="SECOND")

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_nested_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        child=ExampleChild(value=42),
    )

    google = GoogleMessage(
        child={"value": 42},
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_empty_nested_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        child=ExampleChild(),
    )

    google = GoogleMessage(
        child={},
    )

    assert custom.HasField("child") is True
    assert google.HasField("child") is True

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_serialization_accessed_nested_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    _ = custom.child
    _ = google.child

    assert custom.HasField("child") is False
    assert google.HasField("child") is False

    assert custom.SerializeToString() == google.SerializeToString() == b""


def test_message_serialization_modified_nested_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    custom.child.value = 42
    google.child.value = 42

    assert custom.HasField("child") is True
    assert google.HasField("child") is True

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_varints_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        enabled=True,
        count=300,
        mode="SECOND",
    )

    data = google.SerializeToString()

    custom = ExampleMessage()

    result = custom.ParseFromString(data)

    assert result == len(data)
    assert custom.enabled == google.enabled
    assert custom.count == google.count
    assert custom.mode == google.mode


def test_message_parse_varint_presence():
    GoogleMessage = make_example_message()

    google = GoogleMessage(count=0)
    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert custom.count == 0
    assert custom.HasField("count") is True


@pytest.mark.parametrize(
    ("signed32", "signed64"),
    [
        (0, 0),
        (1, 1),
        (-1, -1),
        (2147483647, 9223372036854775807),
        (-2147483648, -9223372036854775808),
    ],
)
def test_message_parse_signed_varints_from_google(
    signed32,
    signed64,
):
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        signed32=signed32,
        signed64=signed64,
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    assert custom.signed32 == google.signed32 == signed32
    assert custom.signed64 == google.signed64 == signed64


def test_message_serialization_signed_matches_google():
    GoogleMessage = make_example_message()

    custom = ExampleMessage(
        signed32=-123,
        signed64=-456,
    )

    google = GoogleMessage(
        signed32=-123,
        signed64=-456,
    )

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_length_delimited_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        data=b"\x00\x01\xffhello",
        name="Hello £ 日本語",
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    assert custom.data == google.data
    assert custom.name == google.name

    assert custom.HasField("data") is True
    assert custom.HasField("name") is True


def test_message_parse_empty_length_delimited_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        data=b"",
        name="",
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    assert custom.data == b""
    assert custom.name == ""

    assert custom.HasField("data") is True
    assert custom.HasField("name") is True


def test_message_parse_nested_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        child={"value": 12345},
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    assert custom.HasField("child") is True
    assert custom.child.value == google.child.value == 12345


def test_message_parse_empty_nested_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        child={},
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    assert custom.HasField("child") is True
    assert google.HasField("child") is True
    assert custom.child.value == google.child.value == 0


def test_message_parse_and_reserialize_matches_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        enabled=True,
        count=300,
        data=b"\x00\x01\xff",
        name="hello",
        mode="SECOND",
        signed32=-123,
        signed64=-456,
        child={"value": 42},
    )

    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert custom.SerializeToString() == data


def test_message_parse_repeated_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        values=[0, 1, 127, 128, 300, 0xFFFFFFFF],
    )

    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert list(custom.values) == list(google.values)


def test_message_parse_repeated_and_reserialize_matches_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        values=[1, 2, 3, 127, 128, 300],
    )

    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert custom.SerializeToString() == data


def test_message_parse_repeated_bytes_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        blobs=[
            b"",
            b"hello",
            b"\x00\x01\xff",
        ],
    )

    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert list(custom.blobs) == list(google.blobs)
    assert custom.SerializeToString() == data


def test_message_parse_repeated_messages_from_google():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        children=[
            {"value": 1},
            {"value": 2},
            {"value": 300},
        ],
    )

    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    assert [child.value for child in custom.children] == [1, 2, 300]
    assert custom.SerializeToString() == data


def test_message_parse_unknown_varint():
    data = (
        _encode_key(2, 0)
        + _encode_varint(123)
        + _encode_key(100, 0)
        + _encode_varint(999)
        + _encode_key(4, 2)
        + _encode_length_delimited(b"hello")
    )

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.count == 123
    assert message.name == "hello"


def test_message_parse_unknown_length_delimited():
    data = (
        _encode_key(2, 0)
        + _encode_varint(123)
        + _encode_key(100, 2)
        + _encode_length_delimited(b"unknown data")
        + _encode_key(4, 2)
        + _encode_length_delimited(b"hello")
    )

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.count == 123
    assert message.name == "hello"


def test_message_parse_truncated_unknown_length_delimited():
    data = _encode_key(100, 2) + b"\x05abc"

    with pytest.raises(DecodeError):
        ExampleMessage().ParseFromString(data)


def test_message_unknown_varint_round_trip():
    data = _encode_key(2, 0) + _encode_varint(123) + _encode_key(100, 0) + _encode_varint(999)

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.count == 123
    assert message.SerializeToString() == data


def test_message_unknown_length_delimited_round_trip():
    data = _encode_key(2, 0) + _encode_varint(123) + _encode_key(100, 2) + _encode_length_delimited(b"unknown")

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.count == 123
    assert message.SerializeToString() == data


def test_message_unknown_between_known_fields_round_trip():
    data = (
        _encode_key(2, 0)
        + _encode_varint(123)
        + _encode_key(100, 0)
        + _encode_varint(999)
        + _encode_key(4, 2)
        + _encode_length_delimited(b"hello")
    )

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.SerializeToString() == data


def test_message_parse_exact_round_trip():
    data = (
        _encode_key(2, 0)
        + _encode_varint(123)
        + _encode_key(100, 0)
        + _encode_varint(999)
        + _encode_key(4, 2)
        + _encode_length_delimited(b"hello")
    )

    message = ExampleMessage()
    message.ParseFromString(data)

    assert message.SerializeToString() == data


def test_message_parse_then_modify():
    GoogleMessage = make_example_message()

    google = GoogleMessage(count=123)
    data = google.SerializeToString()

    custom = ExampleMessage()
    custom.ParseFromString(data)

    custom.count = 456
    google.count = 456

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_then_modify_nested():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        child={"value": 123},
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    custom.child.value = 456
    google.child.value = 456

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_then_modify_repeated():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        values=[1, 2, 3],
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    custom.values.append(300)
    google.values.append(300)

    assert list(custom.values) == list(google.values)
    assert custom.SerializeToString() == google.SerializeToString()


def test_message_modify_repeated_new_message():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    custom.values.append(1)
    custom.values.append(300)

    google.values.append(1)
    google.values.append(300)

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_then_modify_repeated_child():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        children=[
            {"value": 1},
            {"value": 2},
        ],
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    custom.children[0].value = 300
    google.children[0].value = 300

    assert custom.children[0].value == google.children[0].value
    assert custom.SerializeToString() == google.SerializeToString()


def test_message_append_then_modify_repeated_child():
    GoogleMessage = make_example_message()

    custom = ExampleMessage()
    google = GoogleMessage()

    child = ExampleChild(value=123)

    custom.children.append(child)
    google.children.add(value=123)

    assert custom.SerializeToString() == google.SerializeToString()

    child.value = 300
    google.children[0].value = 300

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_parse_append_then_modify_repeated_child():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        children=[{"value": 1}],
    )

    custom = ExampleMessage()
    custom.ParseFromString(google.SerializeToString())

    child = ExampleChild(value=123)

    custom.children.append(child)
    google.children.add(value=123)

    assert custom.SerializeToString() == google.SerializeToString()

    child.value = 300
    google.children[1].value = 300

    assert custom.SerializeToString() == google.SerializeToString()


def test_message_constructor_ignores_none():
    custom = ExampleMessage(
        count=None,
        data=None,
        child=None,
    )

    assert not custom.HasField("count")
    assert not custom.HasField("data")
    assert not custom.HasField("child")
    assert custom.SerializeToString() == b""


def test_google_message_constructor_none():
    GoogleMessage = make_example_message()

    google = GoogleMessage(
        count=None,
        data=None,
        child=None,
    )

    assert google.SerializeToString() == b""


def test_list_fields_empty():
    custom = ExampleMessage()

    assert custom.ListFields() == []


def test_list_fields():
    custom = ExampleMessage(
        enabled=True,
        count=123,
    )

    fields = custom.ListFields()

    assert [(descriptor.name, value) for descriptor, value in fields] == [
        ("enabled", True),
        ("count", 123),
    ]
