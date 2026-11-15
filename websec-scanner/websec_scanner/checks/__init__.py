from . import (
    cookies,
    cors,
    csrf,
    exposure,
    headers,
    injection,
    libraries,
    methods,
    open_redirect,
    tls,
)

ALL_CHECK_MODULES = [
    headers,
    cookies,
    tls,
    cors,
    exposure,
    methods,
    injection,
    open_redirect,
    csrf,
    libraries,
]
