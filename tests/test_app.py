import os

import pytest
from fastapi.testclient import TestClient

from app.main import MARKER, SESSION_COOKIE_NAME, create_app
from app.store import (
    ADMIN_EMAIL,
    ADMIN_ITEM_TITLE,
    MEMBER_EMAIL,
    MEMBER_ITEM_TITLE,
    InMemoryWorkspaceStore,
    PostgresWorkspaceStore,
    purge_workspace_sessions,
    read_workspace_state,
)

TEST_DATABASE_URL = os.getenv('TEST_DATABASE_URL')
SESSION_SECRET = 'test-session-secret'
ADMIN_PASSWORD = 'admin-bootstrap-password'
MEMBER_PASSWORD = 'member-bootstrap-password'


def create_test_client(
    *,
    store: InMemoryWorkspaceStore | PostgresWorkspaceStore | None = None,
    proof_mode: bool = True,
    session_secret: str = SESSION_SECRET,
    session_ttl_seconds: int = 600,
) -> TestClient:
    store_instance = store or InMemoryWorkspaceStore()
    return TestClient(
        create_app(
            store_factory=lambda: store_instance,
            proof_mode=proof_mode,
            session_secret=session_secret,
            session_ttl_seconds=session_ttl_seconds,
            admin_bootstrap_password=ADMIN_PASSWORD,
            member_bootstrap_password=MEMBER_PASSWORD,
        )
    )


def test_proof_reset_auth_and_crud_in_memory() -> None:
    with create_test_client() as client:
        health = client.get('/healthz')
        assert health.status_code == 200
        assert health.json()['store'] == 'InMemoryWorkspaceStore'
        assert health.json()['proof_mode'] is True
        assert health.headers['x-robots-tag'].startswith('noindex')

        index = client.get('/')
        assert index.status_code == 200
        assert MARKER in index.text
        assert index.headers['x-robots-tag'].startswith('noindex')

        robots = client.get('/robots.txt')
        assert robots.status_code == 200
        assert robots.text == 'User-agent: *\nDisallow: /\n'

        assert client.get('/auth/me').status_code == 401
        assert client.get('/items').status_code == 401

        reset = client.post('/proof/reset')
        assert reset.status_code == 200
        reset_payload = reset.json()
        assert reset_payload['admin_user']['email'] == ADMIN_EMAIL
        assert reset_payload['member_user']['email'] == MEMBER_EMAIL
        assert reset_payload['admin_item']['title'] == ADMIN_ITEM_TITLE
        assert reset_payload['member_item']['title'] == MEMBER_ITEM_TITLE
        assert reset_payload['session_count'] == 0

        member_login = client.post(
            '/auth/login',
            json={'email': MEMBER_EMAIL, 'password': MEMBER_PASSWORD},
        )
        assert member_login.status_code == 200
        member_cookie = member_login.headers['set-cookie']
        assert f'{SESSION_COOKIE_NAME}=' in member_cookie
        assert 'HttpOnly' in member_cookie
        assert 'SameSite=lax' in member_cookie
        assert 'Secure' not in member_cookie

        me = client.get('/auth/me')
        assert me.status_code == 200
        assert me.json()['email'] == MEMBER_EMAIL
        assert me.json()['role'] == 'member'

        member_items = client.get('/items')
        assert member_items.status_code == 200
        member_items_payload = member_items.json()
        assert [item['title'] for item in member_items_payload] == [MEMBER_ITEM_TITLE]
        seeded_member_item_id = member_items_payload[0]['item_id']

        assert client.get('/admin/users').status_code == 403

        created = client.post('/items', json={'title': 'MEMBER-CREATED'})
        assert created.status_code == 201
        created_item = created.json()
        assert created_item['owner_email'] == MEMBER_EMAIL
        assert created_item['state'] == 'open'

        patched = client.patch(
            f"/items/{created_item['item_id']}",
            json={'state': 'done', 'title': 'MEMBER-DONE'},
        )
        assert patched.status_code == 200
        assert patched.json()['state'] == 'done'
        assert patched.json()['title'] == 'MEMBER-DONE'

        logout = client.post('/auth/logout')
        assert logout.status_code == 204

        admin_login = client.post(
            '/auth/login',
            json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
        )
        assert admin_login.status_code == 200

        admin_users = client.get('/admin/users')
        assert admin_users.status_code == 200
        assert [user['email'] for user in admin_users.json()] == [ADMIN_EMAIL, MEMBER_EMAIL]

        admin_items = client.get('/items')
        assert admin_items.status_code == 200
        assert {item['title'] for item in admin_items.json()} == {
            ADMIN_ITEM_TITLE,
            MEMBER_ITEM_TITLE,
            'MEMBER-DONE',
        }

        forbidden_member_patch = client.patch(
            f'/items/{seeded_member_item_id}',
            json={'title': 'ADMIN-UPDATED-MEMBER-SEEDED'},
        )
        assert forbidden_member_patch.status_code == 200
        assert forbidden_member_patch.json()['title'] == 'ADMIN-UPDATED-MEMBER-SEEDED'

        deleted = client.delete(f"/items/{created_item['item_id']}")
        assert deleted.status_code == 204


def test_https_cookie_contract_invalid_session_and_proof_gate() -> None:
    with create_test_client() as client:
        disabled_client = create_test_client(proof_mode=False)
        with disabled_client:
            assert disabled_client.post('/proof/reset').status_code == 403

        assert client.post('/proof/reset').status_code == 200

        secure_login = client.post(
            '/auth/login',
            json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
            headers={'x-forwarded-proto': 'https'},
        )
        assert secure_login.status_code == 200
        secure_cookie = secure_login.headers['set-cookie']
        assert 'Secure' in secure_cookie
        assert 'HttpOnly' in secure_cookie
        assert 'SameSite=lax' in secure_cookie

        client.cookies.set(SESSION_COOKIE_NAME, 'tampered.value')
        assert client.get('/auth/me').status_code == 401

        relogin = client.post(
            '/auth/login',
            json={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
        )
        assert relogin.status_code == 200

        logout = client.post('/auth/logout')
        assert logout.status_code == 204
        logout_cookie = logout.headers['set-cookie']
        assert f'{SESSION_COOKIE_NAME}=' in logout_cookie
        assert 'Max-Age=0' in logout_cookie or 'expires=' in logout_cookie.lower()
        assert client.get('/auth/me').status_code == 401


@pytest.mark.integration
@pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason='Integration environment for PostgreSQL is not configured',
)
def test_postgres_sessions_persist_across_restart_and_restore_helpers_work() -> None:
    assert TEST_DATABASE_URL is not None

    store = PostgresWorkspaceStore(TEST_DATABASE_URL)
    session_cookie_value: str | None = None
    with create_test_client(store=store) as client:
        reset = client.post('/proof/reset')
        assert reset.status_code == 200

        login = client.post(
            '/auth/login',
            json={'email': MEMBER_EMAIL, 'password': MEMBER_PASSWORD},
        )
        assert login.status_code == 200
        create_item = client.post('/items', json={'title': 'POSTGRES-ONLY'})
        assert create_item.status_code == 201
        session_cookie_value = client.cookies.get(SESSION_COOKIE_NAME)

    restarted_store = PostgresWorkspaceStore(TEST_DATABASE_URL)
    with create_test_client(store=restarted_store) as restarted:
        assert session_cookie_value is not None
        restarted.cookies.set(SESSION_COOKIE_NAME, session_cookie_value)
        me = restarted.get('/auth/me')
        assert me.status_code == 200
        assert me.json()['email'] == MEMBER_EMAIL

        state = read_workspace_state(TEST_DATABASE_URL)
        assert [user['email'] for user in state['users']] == [ADMIN_EMAIL, MEMBER_EMAIL]
        assert {item['title'] for item in state['items']} == {
            ADMIN_ITEM_TITLE,
            MEMBER_ITEM_TITLE,
            'POSTGRES-ONLY',
        }
        assert state['session_count'] == 1

        deleted_sessions = purge_workspace_sessions(TEST_DATABASE_URL)
        assert deleted_sessions == 1

        purged_state = read_workspace_state(TEST_DATABASE_URL)
        assert purged_state['session_count'] == 0
        assert restarted.get('/auth/me').status_code == 401
