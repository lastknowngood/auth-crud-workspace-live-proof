from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from app.store import ADMIN_EMAIL, MEMBER_EMAIL

MODULE_PATH = Path(__file__).resolve().parents[1] / 'tools' / 'proof' / 'auth_http.py'
SPEC = spec_from_file_location('auth_http_for_tests', MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
AUTH_HTTP = module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH_HTTP)


def test_resolve_login_email_prefers_explicit_email() -> None:
    assert (
        AUTH_HTTP.resolve_login_email(
            role='admin',
            email='custom@example.invalid',
        )
        == 'custom@example.invalid'
    )


def test_resolve_login_email_uses_canonical_seed_addresses() -> None:
    assert AUTH_HTTP.resolve_login_email(role='admin', email=None) == ADMIN_EMAIL
    assert AUTH_HTTP.resolve_login_email(role='member', email=None) == MEMBER_EMAIL
    assert AUTH_HTTP.resolve_login_email(role=None, email=None) is None
