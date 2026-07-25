from uuid import UUID

import pytest
from pymp4.parser import Box as UpstreamBox

from compat.construct import Container
from compat.pymp4 import Box as CompatBox


WIDEVINE_SYSTEM_ID = UUID(
    hex="edef8ba979d64acea3c827dcd51d21ed",
)

KEY_ID_1 = UUID(
    hex="00112233445566778899aabbccddeeff",
)

KEY_ID_2 = UUID(
    hex="ffeeddccbbaa99887766554433221100",
)


def _make_box_data(
    *,
    version=0,
    flags=0,
    system_id=WIDEVINE_SYSTEM_ID,
    key_ids=None,
    init_data=b"",
):
    return {
        "type": b"pssh",
        "version": version,
        "flags": flags,
        "system_ID": system_id,
        "key_IDs": key_ids,
        "init_data": init_data,
    }


def _assert_parsed_boxes_equal(compat, upstream):
    assert compat.type == upstream.type
    assert compat.version == upstream.version
    assert compat.flags == upstream.flags
    assert compat.system_ID == upstream.system_ID
    assert compat.key_IDs == upstream.key_IDs
    assert compat.init_data == upstream.init_data


@pytest.mark.parametrize(
    "init_data",
    [
        b"",
        b"test",
        b"\x00\x01\x02\x03",
        bytes(range(256)),
    ],
)
def test_build_v0_matches_upstream(init_data):
    data = _make_box_data(
        version=0,
        init_data=init_data,
    )

    assert CompatBox.build(data) == UpstreamBox.build(data)


def test_build_nonzero_flags_rejected():
    data = _make_box_data(
        version=0,
        flags=1,
        init_data=b"test-data",
    )

    with pytest.raises(Exception):
        UpstreamBox.build(data)

    with pytest.raises(Exception):
        CompatBox.build(data)


def test_build_v0_with_different_system_id_matches_upstream():
    system_id = UUID(
        hex="9a04f07998404286ab92e65be0885f95",
    )

    data = _make_box_data(
        version=0,
        system_id=system_id,
        init_data=b"test-data",
    )

    assert CompatBox.build(data) == UpstreamBox.build(data)


def test_build_v1_matches_upstream():
    data = _make_box_data(
        version=1,
        key_ids=[
            KEY_ID_1,
            KEY_ID_2,
        ],
        init_data=b"test-data",
    )

    assert CompatBox.build(data) == UpstreamBox.build(data)


def test_build_v1_empty_key_ids_matches_upstream():
    data = _make_box_data(
        version=1,
        key_ids=[],
        init_data=b"test-data",
    )

    assert CompatBox.build(data) == UpstreamBox.build(data)


@pytest.mark.parametrize(
    "init_data",
    [
        b"",
        b"test",
        b"\x00\x01\x02\x03",
        bytes(range(256)),
    ],
)
def test_parse_v0_matches_upstream(init_data):
    source = UpstreamBox.build(
        _make_box_data(
            version=0,
            init_data=init_data,
        ),
    )

    compat = CompatBox.parse(source)
    upstream = UpstreamBox.parse(source)

    _assert_parsed_boxes_equal(compat, upstream)


def test_parse_nonzero_flags_rejected():
    data = _make_box_data(
        version=0,
        flags=0,
        init_data=b"test-data",
    )

    encoded = bytearray(CompatBox.build(data))

    # FullBox layout:
    # 0:4   size
    # 4:8   type
    # 8     version
    # 9:12  flags
    encoded[9:12] = b"\x00\x00\x01"

    with pytest.raises(Exception):
        UpstreamBox.parse(bytes(encoded))

    with pytest.raises(Exception):
        CompatBox.parse(bytes(encoded))


def test_parse_v1_matches_upstream():
    source = UpstreamBox.build(
        _make_box_data(
            version=1,
            key_ids=[
                KEY_ID_1,
                KEY_ID_2,
            ],
            init_data=b"test-data",
        ),
    )

    compat = CompatBox.parse(source)
    upstream = UpstreamBox.parse(source)

    _assert_parsed_boxes_equal(compat, upstream)


def test_parse_v1_empty_key_ids_matches_upstream():
    source = UpstreamBox.build(
        _make_box_data(
            version=1,
            key_ids=[],
            init_data=b"test-data",
        ),
    )

    compat = CompatBox.parse(source)
    upstream = UpstreamBox.parse(source)

    _assert_parsed_boxes_equal(compat, upstream)


@pytest.mark.parametrize(
    "version",
    [
        0,
        1,
    ],
)
def test_round_trip(version):
    key_ids = [KEY_ID_1, KEY_ID_2] if version == 1 else None

    data = _make_box_data(
        version=version,
        flags=0,
        key_ids=key_ids,
        init_data=b"round-trip-data",
    )

    encoded = CompatBox.build(data)
    parsed = CompatBox.parse(encoded)

    assert CompatBox.build(parsed) == encoded


@pytest.mark.parametrize(
    "version",
    [
        0,
        1,
    ],
)
def test_compat_build_can_be_parsed_by_upstream(version):
    key_ids = [KEY_ID_1, KEY_ID_2] if version == 1 else None

    data = _make_box_data(
        version=version,
        flags=0,
        key_ids=key_ids,
        init_data=b"compat-to-upstream",
    )

    encoded = CompatBox.build(data)

    compat = CompatBox.parse(encoded)
    upstream = UpstreamBox.parse(encoded)

    _assert_parsed_boxes_equal(compat, upstream)


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"\x00",
        b"\x00\x00\x00\x20",
        b"\x00\x00\x00\x20pssh",
        b"\x00\x00\x00\x20pssh\x00\x00\x00\x00",
    ],
)
def test_truncated_input_fails(source):
    with pytest.raises(Exception):
        CompatBox.parse(source)

    with pytest.raises(Exception):
        UpstreamBox.parse(source)


def test_parse_returns_compat_container():
    data = _make_box_data(
        version=0,
        init_data=b"test-data",
    )

    encoded = CompatBox.build(data)
    parsed = CompatBox.parse(encoded)

    assert isinstance(parsed, Container)
