from io import BytesIO

import pytest
from pywidevine.device import _Structures as UpstreamStructures

from compat.construct import (
    ConstructError,
    Container,
    _Structures as CompatStructures,
)


def _make_v2_data(
    *,
    type_=2,
    security_level=3,
    private_key=b"private-key",
    client_id=b"client-id",
):
    return (
        b"WVD"
        + bytes((2, type_, security_level, 0))
        + len(private_key).to_bytes(2, "big")
        + private_key
        + len(client_id).to_bytes(2, "big")
        + client_id
    )


def _make_v1_data(
    *,
    type_=2,
    security_level=3,
    private_key=b"private-key",
    client_id=b"client-id",
    vmp=b"vmp-data",
):
    return (
        b"WVD"
        + bytes((1, type_, security_level, 0))
        + len(private_key).to_bytes(2, "big")
        + private_key
        + len(client_id).to_bytes(2, "big")
        + client_id
        + len(vmp).to_bytes(2, "big")
        + vmp
    )


def _assert_parsed_equal(compat, upstream, *, version):
    assert compat.version == upstream.version
    assert compat.type_ == upstream.type_
    assert compat.security_level == upstream.security_level
    assert compat.flags == upstream.flags
    assert compat.private_key == upstream.private_key
    assert compat.client_id == upstream.client_id

    if version == 1:
        assert compat.vmp == upstream.vmp


@pytest.mark.parametrize(
    ("type_", "security_level", "private_key", "client_id"),
    [
        (2, 3, b"private-key", b"client-id"),
        (1, 1, b"key", b"client"),
        (2, 3, b"", b""),
        (2, 3, bytes(range(256)), bytes(range(255, -1, -1))),
    ],
)
def test_parse_v2_matches_upstream(
    type_,
    security_level,
    private_key,
    client_id,
):
    data = _make_v2_data(
        type_=type_,
        security_level=security_level,
        private_key=private_key,
        client_id=client_id,
    )

    compat = CompatStructures.v2.parse(data)
    upstream = UpstreamStructures.v2.parse(data)

    _assert_parsed_equal(
        compat,
        upstream,
        version=2,
    )


def test_parse_v1_matches_upstream():
    data = _make_v1_data()

    compat = CompatStructures.v1.parse(data)
    upstream = UpstreamStructures.v1.parse(data)

    _assert_parsed_equal(
        compat,
        upstream,
        version=1,
    )


@pytest.mark.parametrize(
    "version",
    [
        1,
        2,
    ],
)
def test_header_parse_matches_upstream(version):
    data = _make_v1_data() if version == 1 else _make_v2_data()

    compat = CompatStructures.header.parse(data)
    upstream = UpstreamStructures.header.parse(data)

    assert compat.version == upstream.version


def test_parse_stream_matches_parse():
    data = _make_v2_data()

    parsed = CompatStructures.v2.parse(data)
    streamed = CompatStructures.v2.parse_stream(
        BytesIO(data),
    )

    _assert_parsed_equal(
        streamed,
        parsed,
        version=2,
    )


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"W",
        b"WV",
        b"BAD\x02",
        b"WVD",
        b"WVD\x02",
        b"WVD\x02\x02",
    ],
)
def test_invalid_or_truncated_input_fails(source):
    with pytest.raises(Exception):
        UpstreamStructures.v2.parse(source)

    with pytest.raises(Exception):
        CompatStructures.v2.parse(source)


@pytest.mark.parametrize(
    "source",
    [
        b"WVD\x02\x02\x03",
        b"WVD\x02\x02\x03\x00",
        b"WVD\x02\x02\x03\x00\x00",
    ],
)
def test_compat_truncated_v2_fails(source):
    with pytest.raises(ConstructError):
        CompatStructures.v2.parse(source)


def test_wrong_version_fails():
    data = _make_v1_data()

    with pytest.raises(Exception):
        UpstreamStructures.v2.parse(data)

    with pytest.raises(Exception):
        CompatStructures.v2.parse(data)


def test_unknown_device_type_fails():
    data = _make_v2_data(type_=255)

    with pytest.raises(Exception):
        UpstreamStructures.v2.parse(data)

    with pytest.raises(Exception):
        CompatStructures.v2.parse(data)


@pytest.mark.parametrize(
    ("type_", "security_level"),
    [
        ("ANDROID", 3),
        ("CHROME", 1),
    ],
)
def test_build_v2_matches_upstream(
    type_,
    security_level,
):
    obj = {
        "version": 2,
        "type_": type_,
        "security_level": security_level,
        "flags": {},
        "private_key_len": len(b"private-key"),
        "private_key": b"private-key",
        "client_id_len": len(b"client-id"),
        "client_id": b"client-id",
    }

    assert CompatStructures.v2.build(obj) == UpstreamStructures.v2.build(obj)


def test_build_then_parse_round_trip():
    obj = {
        "version": 2,
        "type_": "ANDROID",
        "security_level": 3,
        "flags": {},
        "private_key_len": len(b"private-key"),
        "private_key": b"private-key",
        "client_id_len": len(b"client-id"),
        "client_id": b"client-id",
    }

    encoded = CompatStructures.v2.build(obj)
    parsed = CompatStructures.v2.parse(encoded)

    assert parsed.version == 2
    assert parsed.type_ == "ANDROID"
    assert parsed.security_level == 3
    assert parsed.private_key == b"private-key"
    assert parsed.client_id == b"client-id"


def test_compat_build_can_be_parsed_by_upstream():
    obj = {
        "version": 2,
        "type_": "ANDROID",
        "security_level": 3,
        "flags": {},
        "private_key_len": len(b"private-key"),
        "private_key": b"private-key",
        "client_id_len": len(b"client-id"),
        "client_id": b"client-id",
    }

    encoded = CompatStructures.v2.build(obj)

    compat = CompatStructures.v2.parse(encoded)
    upstream = UpstreamStructures.v2.parse(encoded)

    _assert_parsed_equal(
        compat,
        upstream,
        version=2,
    )


def test_container_attribute_access():
    container = Container(
        foo="bar",
        number=123,
    )

    assert container.foo == "bar"
    assert container.number == 123

    container.foo = "changed"

    assert container["foo"] == "changed"


def test_construct_error_is_exception():
    assert issubclass(ConstructError, Exception)
