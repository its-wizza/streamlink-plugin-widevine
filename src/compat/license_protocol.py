"""
Minimal replacement for pywidevine.license_protocol_pb2.

Definitions correspond to pywidevine's license_protocol.proto.
"""

from .protobuf import (
    _BOOL,
    _BYTES,
    _ENUM,
    _INT32,
    _INT64,
    _MESSAGE,
    _STRING,
    _UINT32,
    _Field,
    _Message,
    _ProtoEnum,
)


class LicenseType(_ProtoEnum):
    _values = {
        "STREAMING": 1,
        "OFFLINE": 2,
        "AUTOMATIC": 3,
    }


class PlatformVerificationStatus(_ProtoEnum):
    _values = {
        "PLATFORM_UNVERIFIED": 0,
        "PLATFORM_TAMPERED": 1,
        "PLATFORM_SOFTWARE_VERIFIED": 2,
        "PLATFORM_HARDWARE_VERIFIED": 3,
        "PLATFORM_NO_VERIFICATION": 4,
        "PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED": 5,
    }


class LicenseIdentification(_Message):
    _fields = {
        "request_id": _Field(1, _BYTES),
        "session_id": _Field(2, _BYTES),
        "purchase_id": _Field(3, _BYTES),
        "type": _Field(4, _ENUM, enum=LicenseType),
        "version": _Field(5, _INT32),
        "provider_session_token": _Field(6, _BYTES),
    }


class License(_Message):
    class Policy(_Message):
        _fields = {
            "can_play": _Field(1, _BOOL, default=False),
            "can_persist": _Field(2, _BOOL, default=False),
            "can_renew": _Field(3, _BOOL, default=False),
            "rental_duration_seconds": _Field(4, _INT64, default=0),
            "playback_duration_seconds": _Field(5, _INT64, default=0),
            "license_duration_seconds": _Field(6, _INT64, default=0),
            "renewal_recovery_duration_seconds": _Field(7, _INT64, default=0),
            "renewal_server_url": _Field(8, _STRING),
            "renewal_delay_seconds": _Field(9, _INT64, default=0),
            "renewal_retry_interval_seconds": _Field(10, _INT64, default=0),
            "renew_with_usage": _Field(11, _BOOL, default=False),
            "always_include_client_id": _Field(12, _BOOL, default=False),
            "play_start_grace_period_seconds": _Field(13, _INT64, default=0),
            "soft_enforce_playback_duration": _Field(14, _BOOL, default=False),
            "soft_enforce_rental_duration": _Field(15, _BOOL, default=True),
        }

    class KeyContainer(_Message):
        class KeyType(_ProtoEnum):
            _values = {
                "SIGNING": 1,
                "CONTENT": 2,
                "KEY_CONTROL": 3,
                "OPERATOR_SESSION": 4,
                "ENTITLEMENT": 5,
                "OEM_CONTENT": 6,
            }

        class SecurityLevel(_ProtoEnum):
            _values = {
                "SW_SECURE_CRYPTO": 1,
                "SW_SECURE_DECODE": 2,
                "HW_SECURE_CRYPTO": 3,
                "HW_SECURE_DECODE": 4,
                "HW_SECURE_ALL": 5,
            }

        class KeyControl(_Message):
            _fields = {
                "key_control_block": _Field(1, _BYTES),
                "iv": _Field(2, _BYTES),
            }

        class OutputProtection(_Message):
            class HDCP(_ProtoEnum):
                _values = {
                    "HDCP_NONE": 0,
                    "HDCP_V1": 1,
                    "HDCP_V2": 2,
                    "HDCP_V2_1": 3,
                    "HDCP_V2_2": 4,
                    "HDCP_V2_3": 5,
                    "HDCP_NO_DIGITAL_OUTPUT": 0xFF,
                }

            class CGMS(_ProtoEnum):
                _values = {
                    "CGMS_NONE": 42,
                    "COPY_FREE": 0,
                    "COPY_ONCE": 2,
                    "COPY_NEVER": 3,
                }

            class HdcpSrmRule(_ProtoEnum):
                _values = {
                    "HDCP_SRM_RULE_NONE": 0,
                    "CURRENT_SRM": 1,
                }

            _fields = {
                "hdcp": _Field(
                    1,
                    _ENUM,
                    enum=HDCP,
                    default=0,
                ),
                "cgms_flags": _Field(
                    2,
                    _ENUM,
                    enum=CGMS,
                    default=42,
                ),
                "hdcp_srm_rule": _Field(
                    3,
                    _ENUM,
                    enum=HdcpSrmRule,
                    default=0,
                ),
                "disable_analog_output": _Field(
                    4,
                    _BOOL,
                    default=False,
                ),
                "disable_digital_output": _Field(
                    5,
                    _BOOL,
                    default=False,
                ),
            }

        class VideoResolutionConstraint(_Message):
            pass

        class OperatorSessionKeyPermissions(_Message):
            _fields = {
                "allow_encrypt": _Field(1, _BOOL, default=False),
                "allow_decrypt": _Field(2, _BOOL, default=False),
                "allow_sign": _Field(3, _BOOL, default=False),
                "allow_signature_verify": _Field(
                    4,
                    _BOOL,
                    default=False,
                ),
            }

        _fields = {
            "id": _Field(1, _BYTES),
            "iv": _Field(2, _BYTES),
            "key": _Field(3, _BYTES),
            "type": _Field(
                4,
                _ENUM,
                enum=KeyType,
            ),
            "level": _Field(
                5,
                _ENUM,
                enum=SecurityLevel,
                default=1,
            ),
            "required_protection": _Field(
                6,
                _MESSAGE,
                message=OutputProtection,
            ),
            "requested_protection": _Field(
                7,
                _MESSAGE,
                message=OutputProtection,
            ),
            "key_control": _Field(
                8,
                _MESSAGE,
                message=KeyControl,
            ),
            "operator_session_key_permissions": _Field(
                9,
                _MESSAGE,
                message=OperatorSessionKeyPermissions,
            ),
            "video_resolution_constraints": _Field(
                10,
                _MESSAGE,
                message=VideoResolutionConstraint,
                repeated=True,
            ),
            "anti_rollback_usage_table": _Field(
                11,
                _BOOL,
                default=False,
            ),
            "track_label": _Field(
                12,
                _STRING,
            ),
        }

    _fields = {
        "id": _Field(
            1,
            _MESSAGE,
            message=LicenseIdentification,
        ),
        "policy": _Field(
            2,
            _MESSAGE,
            message=Policy,
        ),
        "key": _Field(
            3,
            _MESSAGE,
            message=KeyContainer,
            repeated=True,
        ),
        "license_start_time": _Field(
            4,
            _INT64,
        ),
        "remote_attestation_verified": _Field(
            5,
            _BOOL,
            default=False,
        ),
        "provider_client_token": _Field(
            6,
            _BYTES,
        ),
        "protection_scheme": _Field(
            7,
            _UINT32,
        ),
        "srm_requirement": _Field(
            8,
            _BYTES,
        ),
        "srm_update": _Field(
            9,
            _BYTES,
        ),
        "platform_verification_status": _Field(
            10,
            _ENUM,
            enum=PlatformVerificationStatus,
            default=4,
        ),
        "group_ids": _Field(
            11,
            _BYTES,
            repeated=True,
        ),
    }


License.KeyContainer.VideoResolutionConstraint._fields = {
    "min_resolution_pixels": _Field(
        1,
        _UINT32,
    ),
    "max_resolution_pixels": _Field(
        2,
        _UINT32,
    ),
    "required_protection": _Field(
        3,
        _MESSAGE,
        message=License.KeyContainer.OutputProtection,
    ),
}


class ClientIdentification(_Message):
    class TokenType(_ProtoEnum):
        _values = {
            "KEYBOX": 0,
            "DRM_DEVICE_CERTIFICATE": 1,
            "REMOTE_ATTESTATION_CERTIFICATE": 2,
            "OEM_DEVICE_CERTIFICATE": 3,
        }

    class NameValue(_Message):
        _fields = {
            "name": _Field(1, _STRING),
            "value": _Field(2, _STRING),
        }

    class ClientCapabilities(_Message):
        class HdcpVersion(_ProtoEnum):
            _values = {
                "HDCP_NONE": 0,
                "HDCP_V1": 1,
                "HDCP_V2": 2,
                "HDCP_V2_1": 3,
                "HDCP_V2_2": 4,
                "HDCP_V2_3": 5,
                "HDCP_NO_DIGITAL_OUTPUT": 0xFF,
            }

        class CertificateKeyType(_ProtoEnum):
            _values = {
                "RSA_2048": 0,
                "RSA_3072": 1,
                "ECC_SECP256R1": 2,
                "ECC_SECP384R1": 3,
                "ECC_SECP521R1": 4,
            }

        class AnalogOutputCapabilities(_ProtoEnum):
            _values = {
                "ANALOG_OUTPUT_UNKNOWN": 0,
                "ANALOG_OUTPUT_NONE": 1,
                "ANALOG_OUTPUT_SUPPORTED": 2,
                "ANALOG_OUTPUT_SUPPORTS_CGMS_A": 3,
            }

        _fields = {
            "client_token": _Field(1, _BOOL, default=False),
            "session_token": _Field(2, _BOOL, default=False),
            "video_resolution_constraints": _Field(
                3,
                _BOOL,
                default=False,
            ),
            "max_hdcp_version": _Field(
                4,
                _ENUM,
                enum=HdcpVersion,
                default=0,
            ),
            "oem_crypto_api_version": _Field(5, _UINT32),
            "anti_rollback_usage_table": _Field(
                6,
                _BOOL,
                default=False,
            ),
            "srm_version": _Field(7, _UINT32),
            "can_update_srm": _Field(8, _BOOL, default=False),
            "supported_certificate_key_type": _Field(
                9,
                _ENUM,
                repeated=True,
                enum=CertificateKeyType,
            ),
            "analog_output_capabilities": _Field(
                10,
                _ENUM,
                enum=AnalogOutputCapabilities,
                default=0,
            ),
            "can_disable_analog_output": _Field(
                11,
                _BOOL,
                default=False,
            ),
            "resource_rating_tier": _Field(
                12,
                _UINT32,
                default=0,
            ),
        }

    class ClientCredentials(_Message):
        _fields = {
            "type": _Field(
                1,
                _ENUM,
                enum=None,  # assigned below
                default=0,
            ),
            "token": _Field(2, _BYTES),
        }

    _fields = {
        "type": _Field(
            1,
            _ENUM,
            enum=TokenType,
            default=0,
        ),
        "token": _Field(2, _BYTES),
        "client_info": _Field(
            3,
            _MESSAGE,
            repeated=True,
            message=NameValue,
        ),
        "provider_client_token": _Field(4, _BYTES),
        "license_counter": _Field(5, _UINT32),
        "client_capabilities": _Field(
            6,
            _MESSAGE,
            message=ClientCapabilities,
        ),
        "vmp_data": _Field(7, _BYTES),
        "device_credentials": _Field(
            8,
            _MESSAGE,
            repeated=True,
            message=ClientCredentials,
        ),
    }


ClientIdentification.ClientCredentials._fields["type"].enum = ClientIdentification.TokenType


class EncryptedClientIdentification(_Message):
    _fields = {
        "provider_id": _Field(1, _STRING),
        "service_certificate_serial_number": _Field(2, _BYTES),
        "encrypted_client_id": _Field(3, _BYTES),
        "encrypted_client_id_iv": _Field(4, _BYTES),
        "encrypted_privacy_key": _Field(5, _BYTES),
    }


class LicenseRequest(_Message):
    class RequestType(_ProtoEnum):
        _values = {
            "NEW": 1,
            "RENEWAL": 2,
            "RELEASE": 3,
        }

    class ProtocolVersion(_ProtoEnum):
        _values = {
            "VERSION_2_0": 20,
            "VERSION_2_1": 21,
            "VERSION_2_2": 22,
        }

    class ContentIdentification(_Message):
        class WidevinePsshData(_Message):
            _fields = {
                "pssh_data": _Field(
                    1,
                    _BYTES,
                    repeated=True,
                ),
                "license_type": _Field(
                    2,
                    _ENUM,
                    enum=LicenseType,
                    default=1,
                ),
                "request_id": _Field(
                    3,
                    _BYTES,
                ),
            }

        _fields = {
            "widevine_pssh_data": _Field(
                1,
                _MESSAGE,
                message=WidevinePsshData,
            ),
        }

    _fields = {
        "client_id": _Field(
            1,
            _MESSAGE,
            message=ClientIdentification,
        ),
        "content_id": _Field(
            2,
            _MESSAGE,
            message=ContentIdentification,
        ),
        "type": _Field(
            3,
            _ENUM,
            enum=RequestType,
            default=1,
        ),
        "request_time": _Field(
            4,
            _INT64,
        ),
        "key_control_nonce_deprecated": _Field(
            5,
            _BYTES,
        ),
        "protocol_version": _Field(
            6,
            _ENUM,
            enum=ProtocolVersion,
            default=20,
        ),
        "key_control_nonce": _Field(
            7,
            _UINT32,
        ),
        "encrypted_client_id": _Field(
            8,
            _MESSAGE,
            message=EncryptedClientIdentification,
        ),
    }


class MetricData(_Message):
    class MetricType(_ProtoEnum):
        _values = {
            "LATENCY": 1,
            "TIMESTAMP": 2,
        }

    class TypeValue(_Message):
        _fields = {
            "type": _Field(
                1,
                _ENUM,
                enum=None,
            ),
            "value": _Field(
                2,
                _INT64,
                default=0,
            ),
        }

    _fields = {
        "stage_name": _Field(
            1,
            _STRING,
        ),
        "metric_data": _Field(
            2,
            _MESSAGE,
            repeated=True,
            message=TypeValue,
        ),
    }


MetricData.TypeValue._fields["type"].enum = MetricData.MetricType


class VersionInfo(_Message):
    _fields = {
        "license_sdk_version": _Field(
            1,
            _STRING,
        ),
        "license_service_version": _Field(
            2,
            _STRING,
        ),
    }


class SignedMessage(_Message):
    class MessageType(_ProtoEnum):
        _values = {
            "LICENSE_REQUEST": 1,
            "LICENSE": 2,
            "ERROR_RESPONSE": 3,
            "SERVICE_CERTIFICATE_REQUEST": 4,
            "SERVICE_CERTIFICATE": 5,
            "SUB_LICENSE": 6,
            "CAS_LICENSE_REQUEST": 7,
            "CAS_LICENSE": 8,
            "EXTERNAL_LICENSE_REQUEST": 9,
            "EXTERNAL_LICENSE": 10,
        }

    class SessionKeyType(_ProtoEnum):
        _values = {
            "UNDEFINED": 0,
            "WRAPPED_AES_KEY": 1,
            "EPHERMERAL_ECC_PUBLIC_KEY": 2,
        }

    _fields = {
        "type": _Field(
            1,
            _ENUM,
            enum=MessageType,
        ),
        "msg": _Field(
            2,
            _BYTES,
        ),
        "signature": _Field(
            3,
            _BYTES,
        ),
        "session_key": _Field(
            4,
            _BYTES,
        ),
        "remote_attestation": _Field(
            5,
            _BYTES,
        ),
        "metric_data": _Field(
            6,
            _MESSAGE,
            repeated=True,
            message=MetricData,
        ),
        "service_version_info": _Field(
            7,
            _MESSAGE,
            message=VersionInfo,
        ),
        "session_key_type": _Field(
            8,
            _ENUM,
            enum=SessionKeyType,
            default=1,
        ),
        "oemcrypto_core_message": _Field(
            9,
            _BYTES,
        ),
    }


class HashAlgorithmProto(_ProtoEnum):
    _values = {
        "HASH_ALGORITHM_UNSPECIFIED": 0,
        "HASH_ALGORITHM_SHA_1": 1,
        "HASH_ALGORITHM_SHA_256": 2,
        "HASH_ALGORITHM_SHA_384": 3,
    }


class DrmCertificate(_Message):
    class Type(_ProtoEnum):
        _values = {
            "ROOT": 0,
            "DEVICE_MODEL": 1,
            "DEVICE": 2,
            "SERVICE": 3,
            "PROVISIONER": 4,
        }

    class ServiceType(_ProtoEnum):
        _values = {
            "UNKNOWN_SERVICE_TYPE": 0,
            "LICENSE_SERVER_SDK": 1,
            "LICENSE_SERVER_PROXY_SDK": 2,
            "PROVISIONING_SDK": 3,
            "CAS_PROXY_SDK": 4,
        }

    class Algorithm(_ProtoEnum):
        _values = {
            "UNKNOWN_ALGORITHM": 0,
            "RSA": 1,
            "ECC_SECP256R1": 2,
            "ECC_SECP384R1": 3,
            "ECC_SECP521R1": 4,
        }

    class EncryptionKey(_Message):
        _fields = {
            "public_key": _Field(
                1,
                _BYTES,
            ),
            "algorithm": _Field(
                2,
                _ENUM,
                enum=None,
                default=1,
            ),
        }

    _fields = {
        "type": _Field(
            1,
            _ENUM,
            enum=Type,
        ),
        "serial_number": _Field(
            2,
            _BYTES,
        ),
        "creation_time_seconds": _Field(
            3,
            _UINT32,
        ),
        "public_key": _Field(
            4,
            _BYTES,
        ),
        "system_id": _Field(
            5,
            _UINT32,
        ),
        "test_device_deprecated": _Field(
            6,
            _BOOL,
        ),
        "provider_id": _Field(
            7,
            _STRING,
        ),
        "service_types": _Field(
            8,
            _ENUM,
            repeated=True,
            enum=ServiceType,
        ),
        "algorithm": _Field(
            9,
            _ENUM,
            enum=Algorithm,
            default=1,
        ),
        "rot_id": _Field(
            10,
            _BYTES,
        ),
        "encryption_key": _Field(
            11,
            _MESSAGE,
            message=EncryptionKey,
        ),
        "expiration_time_seconds": _Field(
            12,
            _UINT32,
        ),
    }


DrmCertificate.EncryptionKey._fields["algorithm"].enum = DrmCertificate.Algorithm


class SignedDrmCertificate(_Message):
    _fields = {
        "drm_certificate": _Field(
            1,
            _BYTES,
        ),
        "signature": _Field(
            2,
            _BYTES,
        ),
        "signer": _Field(
            3,
            _MESSAGE,
            message=None,
        ),
        "hash_algorithm": _Field(
            4,
            _ENUM,
            enum=HashAlgorithmProto,
        ),
    }


SignedDrmCertificate._fields["signer"].message = SignedDrmCertificate


class FileHashes(_Message):
    class Signature(_Message):
        _fields = {
            "filename": _Field(1, _STRING),
            "test_signing": _Field(2, _BOOL),
            "SHA512Hash": _Field(3, _BYTES),
            "main_exe": _Field(4, _BOOL),
            "signature": _Field(5, _BYTES),
        }

    _fields = {
        "signer": _Field(1, _BYTES),
        "signatures": _Field(
            2,
            _MESSAGE,
            message=Signature,
            repeated=True,
        ),
    }


class WidevinePsshData(_Message):
    class Type(_ProtoEnum):
        _values = {
            "SINGLE": 0,
            "ENTITLEMENT": 1,
            "ENTITLED_KEY": 2,
        }

    class EntitledKey(_Message):
        _fields = {
            "entitlement_key_id": _Field(1, _BYTES),
            "key_id": _Field(2, _BYTES),
            "key": _Field(3, _BYTES),
            "iv": _Field(4, _BYTES),
            "entitlement_key_size_bytes": _Field(
                5,
                _UINT32,
                default=32,
            ),
        }

    class Algorithm(_ProtoEnum):
        _values = {
            "UNENCRYPTED": 0,
            "AESCTR": 1,
        }

    _fields = {
        "algorithm": _Field(
            1,
            _ENUM,
            enum=Algorithm,
        ),
        "key_ids": _Field(
            2,
            _BYTES,
            repeated=True,
        ),
        "provider": _Field(
            3,
            _STRING,
        ),
        "content_id": _Field(
            4,
            _BYTES,
        ),
        "track_type": _Field(
            5,
            _STRING,
        ),
        "policy": _Field(
            6,
            _STRING,
        ),
        "crypto_period_index": _Field(
            7,
            _UINT32,
        ),
        "grouped_license": _Field(
            8,
            _BYTES,
        ),
        "protection_scheme": _Field(
            9,
            _UINT32,
        ),
        "crypto_period_seconds": _Field(
            10,
            _UINT32,
        ),
        "type": _Field(
            11,
            _ENUM,
            enum=Type,
            default=0,
        ),
        "key_sequence": _Field(
            12,
            _UINT32,
        ),
        "group_ids": _Field(
            13,
            _BYTES,
            repeated=True,
        ),
        "entitled_keys": _Field(
            14,
            _MESSAGE,
            message=EntitledKey,
            repeated=True,
        ),
        "video_feature": _Field(
            15,
            _STRING,
        ),
    }
