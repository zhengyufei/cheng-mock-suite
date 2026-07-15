"""Protocol paths and subtype coverage for the ministry platform mock."""

from __future__ import annotations


# mock 向后端发送请求时覆盖的后端入口。
BACKEND_RECEIVE_PATH = "/api/ministry/receive"
BACKEND_FILE_PATH = "/api/ministry/file"

# 后端出站时由 mock 暴露的部平台入口。
PLATFORM_RECEIVE_PATH = "/ministry/receive"
PLATFORM_FILE_PATH = "/ministry/file"

# 当前后端文件上传仍使用此兼容路径。
LEGACY_PLATFORM_FILE_UPLOAD_PATH = "/api/v1/platformFileUpload"

PLATFORM_POST_PATHS = {
    PLATFORM_RECEIVE_PATH,
    PLATFORM_FILE_PATH,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
}

# 当前协议门禁与已知出站服务覆盖的子类型。
KNOWN_PROTOCOL_SUBTYPES = {
    21,
    22,
    31,
    32,
    33,
    34,
    41,
    42,
    43,
    44,
    101,
    104,
    105,
    201,
    202,
    203,
    301,
    302,
    303,
    304,
    305,
    306,
    307,
    308,
    309,
}

# V2.2 扩展接口目录；协议编号集中维护，避免 fixture、校验器和响应注入各自漂移。
WORK_ORDER_RESPONSE_SUBTYPES = {31: 41, 32: 42, 33: 43, 34: 44}
PRODUCT_WORK_ORDER_RESPONSE_SUBTYPES = {11: 21, 12: 22}
PRODUCT_WORK_ORDER_REQUEST_SUBTYPES = frozenset(PRODUCT_WORK_ORDER_RESPONSE_SUBTYPES)
PRODUCT_WORK_ORDER_REPLY_SUBTYPES = frozenset(PRODUCT_WORK_ORDER_RESPONSE_SUBTYPES.values())
WORK_ORDER_STATUS_SLOTS = (0, 1, 2, 3, 5, 6, 7, 8, 9, 10)
WORK_ORDER_TARGET_STATUSES = {
    31: frozenset({1}),
    32: frozenset({2, 3, 8}),
    33: frozenset({5, 9}),
    34: frozenset({6, 7, 10}),
}
WORK_ORDER_PROC_METHODS = {31: 1020, 32: 1026, 33: 1050, 34: 1060}
INTERFACE_ORDER_SUBTYPES = {11: 104, 12: 105}
INTERFACE_TEST_TYPES = {17: 1, 18: 2, 19: 3, 21: 5, 22: 6}
TEST_DATA_SUBTYPE = 307
TEST_DATA_SVC_TYPES = {1: (9,), 2: (10,), 3: (11, 13), 5: (12,), 6: (11, 13, 12)}
TEST_DATA_OPTIONAL_SVC_TYPES: dict[int, tuple[int, ...]] = {}
TEST_TYPE_INTERFACES = {test_type: interface_no for interface_no, test_type in INTERFACE_TEST_TYPES.items()}
OUTBOUND_DATA_SUBTYPES = {26: 202, 27: 203}
PLATFORM_RECEIVE_SUBTYPE_INTERFACES = {
    21: 6,
    22: 6,
    101: 8,
    303: 29,
    304: 30,
    305: 31,
    306: 32,
    **{subtype: 4 for subtype in WORK_ORDER_RESPONSE_SUBTYPES.values()},
    **{subtype: interface_no for interface_no, subtype in INTERFACE_ORDER_SUBTYPES.items()},
    **{subtype: interface_no for interface_no, subtype in OUTBOUND_DATA_SUBTYPES.items()},
}
FILE_REQUIRED_CTX_CODES = frozenset({2, 5, 6})
PASSWORD_DICTIONARY_SVC_TYPE = 8
SYSTEM_VULNERABILITY_SVC_TYPE = 12
FILE_INFO_KEYS = frozenset({"name", "dataType", "objectID", "svcType", "reserved"})
FILE_METADATA_KEYS = frozenset(
    {
        "dataType",
        "dataSubType",
        "sign",
        "timeStamp",
    }
)
ADDITIONAL_INTERFACE_DIRECTIONS = {
    3: "ministry_to_province",
    4: "province_to_ministry",
    11: "province_to_ministry",
    12: "province_to_ministry",
    17: "ministry_to_province",
    18: "ministry_to_province",
    19: "ministry_to_province",
    21: "ministry_to_province",
    22: "ministry_to_province",
    26: "province_to_ministry",
    27: "province_to_ministry",
}
SUPPORTED_SCENARIOS = (
    "success",
    "reject",
    "interface11_failure",
    "interface12_failure",
    "business202_failure",
    "business203_failure",
    "timeout",
    "duplicate",
    "file_completed",
    "file_failed",
    "unpack_failed",
    "file_receiving",
    "file_partial",
)

FEATURE_INTERFACE_COVERAGE = {
    "backend_receive": BACKEND_RECEIVE_PATH,
    "backend_file": BACKEND_FILE_PATH,
    "platform_receive": PLATFORM_RECEIVE_PATH,
    "platform_file": PLATFORM_FILE_PATH,
    "legacy_platform_file": LEGACY_PLATFORM_FILE_UPLOAD_PATH,
}

