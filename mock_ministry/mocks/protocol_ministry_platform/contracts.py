"""Protocol paths and subtype coverage for the ministry platform mock."""

from __future__ import annotations


# Backend entrypoints exercised by this feature when the mock sends requests.
BACKEND_RECEIVE_PATH = "/api/ministry/receive"
BACKEND_FILE_PATH = "/api/ministry/file"

# Ministry-side endpoints exposed by this mock when the backend pushes data out.
PLATFORM_RECEIVE_PATH = "/ministry/receive"
PLATFORM_FILE_PATH = "/ministry/file"

# Current backend file upload implementation still posts this legacy/current path.
LEGACY_PLATFORM_FILE_UPLOAD_PATH = "/api/v1/platformFileUpload"

PLATFORM_POST_PATHS = {
    PLATFORM_RECEIVE_PATH,
    PLATFORM_FILE_PATH,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
}

# Subtypes covered by current protocol-gate work and known outbound services.
KNOWN_PROTOCOL_SUBTYPES = {
    104,
    105,
    201,
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

FEATURE_INTERFACE_COVERAGE = {
    "backend_receive": BACKEND_RECEIVE_PATH,
    "backend_file": BACKEND_FILE_PATH,
    "platform_receive": PLATFORM_RECEIVE_PATH,
    "platform_file": PLATFORM_FILE_PATH,
    "legacy_platform_file": LEGACY_PLATFORM_FILE_UPLOAD_PATH,
}

