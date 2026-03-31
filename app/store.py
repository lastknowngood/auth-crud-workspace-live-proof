import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, TypedDict, cast

import psycopg
from psycopg.rows import dict_row

from .models import (
    ItemRecord,
    ItemState,
    ProofResetRecord,
    Role,
    StoredItem,
    StoredSession,
    StoredUser,
    UserRecord,
)

ADMIN_EMAIL = 'admin@example.test'
MEMBER_EMAIL = 'member@example.test'
ADMIN_ITEM_TITLE = 'ADMIN-SEEDED'
MEMBER_ITEM_TITLE = 'MEMBER-SEEDED'

USERS_SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
'''

ITEMS_SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS items (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
'''

ITEMS_INDEX_SQL = '''
CREATE INDEX IF NOT EXISTS idx_items_owner_user_id
ON items (owner_user_id, created_at);
'''

SESSIONS_SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
'''

SESSIONS_INDEX_SQL = '''
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
ON sessions (user_id, expires_at);
'''


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_role(value: str) -> Role:
    role = value.strip().lower()
    if role not in {'admin', 'member'}:
        raise ValueError(f'Unsupported role: {value!r}')
    return cast(Role, role)


def normalize_state(value: str) -> ItemState:
    state = value.strip().lower()
    if state not in {'open', 'done'}:
        raise ValueError(f'Unsupported item state: {value!r}')
    return cast(ItemState, state)


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    effective_salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode('utf-8'),
        salt=effective_salt,
        n=2**12,
        r=8,
        p=1,
        dklen=32,
    )
    return f'scrypt$1${effective_salt.hex()}${digest.hex()}'


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, version, salt_hex, digest_hex = encoded_hash.split('$', 3)
    except ValueError:
        return False
    if algorithm != 'scrypt' or version != '1':
        return False
    expected = hash_password(password, salt=bytes.fromhex(salt_hex))
    return hmac.compare_digest(expected, encoded_hash)


def hash_session_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()


def _row_to_user(row: dict[str, object]) -> StoredUser:
    return StoredUser(
        user_id=str(row['id']),
        email=str(row['email']),
        role=normalize_role(str(row['role'])),
        password_hash=str(row['password_hash']),
        created_at=cast(datetime, row['created_at']),
        updated_at=cast(datetime, row['updated_at']),
    )


def _row_to_item(row: dict[str, object]) -> StoredItem:
    return StoredItem(
        item_id=str(row['id']),
        owner_user_id=str(row['owner_user_id']),
        owner_email=str(row['owner_email']),
        title=str(row['title']),
        state=normalize_state(str(row['state'])),
        created_at=cast(datetime, row['created_at']),
        updated_at=cast(datetime, row['updated_at']),
    )


def _row_to_session(row: dict[str, object]) -> StoredSession:
    return StoredSession(
        token_hash=str(row['token_hash']),
        user_id=str(row['user_id']),
        expires_at=cast(datetime, row['expires_at']),
        created_at=cast(datetime, row['created_at']),
    )


class WorkspaceStore:
    def reset_proof_state(
        self,
        *,
        admin_password: str,
        member_password: str,
    ) -> ProofResetRecord:
        raise NotImplementedError

    def authenticate_user(self, *, email: str, password: str) -> StoredUser | None:
        raise NotImplementedError

    def create_session(
        self,
        *,
        user_id: str,
        now: datetime,
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        raise NotImplementedError

    def get_user_for_session(self, *, raw_token: str, now: datetime) -> StoredUser | None:
        raise NotImplementedError

    def delete_session(self, *, raw_token: str) -> bool:
        raise NotImplementedError

    def purge_sessions(self) -> int:
        raise NotImplementedError

    def list_users(self) -> list[UserRecord]:
        raise NotImplementedError

    def list_items_for_user(self, *, viewer: StoredUser) -> list[ItemRecord]:
        raise NotImplementedError

    def get_item(self, *, item_id: str) -> StoredItem | None:
        raise NotImplementedError

    def create_item(
        self,
        *,
        owner_user_id: str,
        title: str,
        state: ItemState,
        now: datetime,
    ) -> ItemRecord:
        raise NotImplementedError

    def update_item(
        self,
        *,
        item_id: str,
        title: str | None,
        state: ItemState | None,
        now: datetime,
    ) -> ItemRecord | None:
        raise NotImplementedError

    def delete_item(self, *, item_id: str) -> bool:
        raise NotImplementedError


class WorkspaceStatePayload(TypedDict):
    users: list[dict[str, object]]
    items: list[dict[str, object]]
    session_count: int


class InMemoryWorkspaceStore(WorkspaceStore):
    def __init__(self) -> None:
        self._lock = Lock()
        self._users: dict[str, StoredUser] = {}
        self._users_by_email: dict[str, str] = {}
        self._items: dict[str, StoredItem] = {}
        self._sessions: dict[str, StoredSession] = {}

    def reset_proof_state(
        self,
        *,
        admin_password: str,
        member_password: str,
    ) -> ProofResetRecord:
        now = utcnow()
        admin_user = StoredUser(
            user_id=str(uuid.uuid4()),
            email=ADMIN_EMAIL,
            role='admin',
            password_hash=hash_password(admin_password),
            created_at=now,
            updated_at=now,
        )
        member_user = StoredUser(
            user_id=str(uuid.uuid4()),
            email=MEMBER_EMAIL,
            role='member',
            password_hash=hash_password(member_password),
            created_at=now,
            updated_at=now,
        )
        admin_item = StoredItem(
            item_id=str(uuid.uuid4()),
            owner_user_id=admin_user.user_id,
            owner_email=admin_user.email,
            title=ADMIN_ITEM_TITLE,
            state='open',
            created_at=now,
            updated_at=now,
        )
        member_item = StoredItem(
            item_id=str(uuid.uuid4()),
            owner_user_id=member_user.user_id,
            owner_email=member_user.email,
            title=MEMBER_ITEM_TITLE,
            state='open',
            created_at=now,
            updated_at=now,
        )
        with self._lock:
            self._users = {
                admin_user.user_id: admin_user,
                member_user.user_id: member_user,
            }
            self._users_by_email = {
                admin_user.email: admin_user.user_id,
                member_user.email: member_user.user_id,
            }
            self._items = {
                admin_item.item_id: admin_item,
                member_item.item_id: member_item,
            }
            self._sessions = {}
        return ProofResetRecord(
            admin_user=admin_user.to_record(),
            member_user=member_user.to_record(),
            admin_item=admin_item.to_record(),
            member_item=member_item.to_record(),
            session_count=0,
        )

    def authenticate_user(self, *, email: str, password: str) -> StoredUser | None:
        normalized_email = email.strip().lower()
        with self._lock:
            user_id = self._users_by_email.get(normalized_email)
            if user_id is None:
                return None
            user = self._users[user_id]
        if not verify_password(password, user.password_hash):
            return None
        return user

    def create_session(
        self,
        *,
        user_id: str,
        now: datetime,
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_session_token(raw_token)
        session = StoredSession(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=now + timedelta(seconds=ttl_seconds),
            created_at=now,
        )
        with self._lock:
            self._sessions[token_hash] = session
        return raw_token, session.expires_at

    def get_user_for_session(self, *, raw_token: str, now: datetime) -> StoredUser | None:
        token_hash = hash_session_token(raw_token)
        with self._lock:
            session = self._sessions.get(token_hash)
            if session is None:
                return None
            if session.expires_at <= now:
                del self._sessions[token_hash]
                return None
            return self._users.get(session.user_id)

    def delete_session(self, *, raw_token: str) -> bool:
        token_hash = hash_session_token(raw_token)
        with self._lock:
            return self._sessions.pop(token_hash, None) is not None

    def purge_sessions(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions = {}
        return count

    def list_users(self) -> list[UserRecord]:
        with self._lock:
            users = sorted(self._users.values(), key=lambda user: user.email)
            return [user.to_record() for user in users]

    def list_items_for_user(self, *, viewer: StoredUser) -> list[ItemRecord]:
        with self._lock:
            items = sorted(
                self._items.values(),
                key=lambda item: (item.owner_email, item.title, item.item_id),
            )
            visible_items = items if viewer.role == 'admin' else [
                item for item in items if item.owner_user_id == viewer.user_id
            ]
            return [item.to_record() for item in visible_items]

    def get_item(self, *, item_id: str) -> StoredItem | None:
        with self._lock:
            return self._items.get(item_id)

    def create_item(
        self,
        *,
        owner_user_id: str,
        title: str,
        state: ItemState,
        now: datetime,
    ) -> ItemRecord:
        with self._lock:
            owner = self._users[owner_user_id]
            item = StoredItem(
                item_id=str(uuid.uuid4()),
                owner_user_id=owner_user_id,
                owner_email=owner.email,
                title=title,
                state=normalize_state(state),
                created_at=now,
                updated_at=now,
            )
            self._items[item.item_id] = item
        return item.to_record()

    def update_item(
        self,
        *,
        item_id: str,
        title: str | None,
        state: ItemState | None,
        now: datetime,
    ) -> ItemRecord | None:
        with self._lock:
            item = self._items.get(item_id)
            if item is None:
                return None
            updated = StoredItem(
                item_id=item.item_id,
                owner_user_id=item.owner_user_id,
                owner_email=item.owner_email,
                title=title if title is not None else item.title,
                state=normalize_state(state) if state is not None else item.state,
                created_at=item.created_at,
                updated_at=now,
            )
            self._items[item_id] = updated
        return updated.to_record()

    def delete_item(self, *, item_id: str) -> bool:
        with self._lock:
            return self._items.pop(item_id, None) is not None


class PostgresWorkspaceStore(WorkspaceStore):
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url
        self.ensure_schema()

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self._database_url)

    def ensure_schema(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(USERS_SCHEMA_SQL)
                cur.execute(ITEMS_SCHEMA_SQL)
                cur.execute(ITEMS_INDEX_SQL)
                cur.execute(SESSIONS_SCHEMA_SQL)
                cur.execute(SESSIONS_INDEX_SQL)
            conn.commit()

    def reset_proof_state(
        self,
        *,
        admin_password: str,
        member_password: str,
    ) -> ProofResetRecord:
        now = utcnow()
        admin_user = StoredUser(
            user_id=str(uuid.uuid4()),
            email=ADMIN_EMAIL,
            role='admin',
            password_hash=hash_password(admin_password),
            created_at=now,
            updated_at=now,
        )
        member_user = StoredUser(
            user_id=str(uuid.uuid4()),
            email=MEMBER_EMAIL,
            role='member',
            password_hash=hash_password(member_password),
            created_at=now,
            updated_at=now,
        )
        admin_item = StoredItem(
            item_id=str(uuid.uuid4()),
            owner_user_id=admin_user.user_id,
            owner_email=admin_user.email,
            title=ADMIN_ITEM_TITLE,
            state='open',
            created_at=now,
            updated_at=now,
        )
        member_item = StoredItem(
            item_id=str(uuid.uuid4()),
            owner_user_id=member_user.user_id,
            owner_email=member_user.email,
            title=MEMBER_ITEM_TITLE,
            state='open',
            created_at=now,
            updated_at=now,
        )
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM sessions')
                cur.execute('DELETE FROM items')
                cur.execute('DELETE FROM users')
                cur.execute(
                    '''
                    INSERT INTO users (id, email, role, password_hash, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ''',
                    (
                        admin_user.user_id,
                        admin_user.email,
                        admin_user.role,
                        admin_user.password_hash,
                        admin_user.created_at,
                        admin_user.updated_at,
                    ),
                )
                cur.execute(
                    '''
                    INSERT INTO users (id, email, role, password_hash, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ''',
                    (
                        member_user.user_id,
                        member_user.email,
                        member_user.role,
                        member_user.password_hash,
                        member_user.created_at,
                        member_user.updated_at,
                    ),
                )
                cur.execute(
                    '''
                    INSERT INTO items (id, owner_user_id, title, state, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ''',
                    (
                        admin_item.item_id,
                        admin_item.owner_user_id,
                        admin_item.title,
                        admin_item.state,
                        admin_item.created_at,
                        admin_item.updated_at,
                    ),
                )
                cur.execute(
                    '''
                    INSERT INTO items (id, owner_user_id, title, state, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ''',
                    (
                        member_item.item_id,
                        member_item.owner_user_id,
                        member_item.title,
                        member_item.state,
                        member_item.created_at,
                        member_item.updated_at,
                    ),
                )
            conn.commit()
        return ProofResetRecord(
            admin_user=admin_user.to_record(),
            member_user=member_user.to_record(),
            admin_item=admin_item.to_record(),
            member_item=member_item.to_record(),
            session_count=0,
        )

    def authenticate_user(self, *, email: str, password: str) -> StoredUser | None:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    'SELECT * FROM users WHERE email = %s',
                    (email.strip().lower(),),
                )
                row = cur.fetchone()
        if row is None:
            return None
        user = _row_to_user(cast(dict[str, object], row))
        if not verify_password(password, user.password_hash):
            return None
        return user

    def create_session(
        self,
        *,
        user_id: str,
        now: datetime,
        ttl_seconds: int,
    ) -> tuple[str, datetime]:
        raw_token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    '''
                    INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
                    VALUES (%s, %s, %s, %s)
                    ''',
                    (hash_session_token(raw_token), user_id, expires_at, now),
                )
            conn.commit()
        return raw_token, expires_at

    def get_user_for_session(self, *, raw_token: str, now: datetime) -> StoredUser | None:
        token_hash = hash_session_token(raw_token)
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    '''
                    SELECT s.token_hash, s.user_id, s.expires_at, s.created_at
                    FROM sessions AS s
                    WHERE s.token_hash = %s
                    ''',
                    (token_hash,),
                )
                session_row = cur.fetchone()
                if session_row is None:
                    return None
                session = _row_to_session(cast(dict[str, object], session_row))
                if session.expires_at <= now:
                    cur.execute('DELETE FROM sessions WHERE token_hash = %s', (token_hash,))
                    conn.commit()
                    return None
                cur.execute('SELECT * FROM users WHERE id = %s', (session.user_id,))
                user_row = cur.fetchone()
        return None if user_row is None else _row_to_user(cast(dict[str, object], user_row))

    def delete_session(self, *, raw_token: str) -> bool:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'DELETE FROM sessions WHERE token_hash = %s',
                    (hash_session_token(raw_token),),
                )
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted

    def purge_sessions(self) -> int:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM sessions')
                deleted = cur.rowcount
            conn.commit()
        return deleted

    def list_users(self) -> list[UserRecord]:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute('SELECT * FROM users ORDER BY email ASC')
                rows = cur.fetchall()
        return [_row_to_user(cast(dict[str, object], row)).to_record() for row in rows]

    def list_items_for_user(self, *, viewer: StoredUser) -> list[ItemRecord]:
        parameters: tuple[object, ...] = ()
        query = '''
            SELECT i.*, u.email AS owner_email
            FROM items AS i
            JOIN users AS u ON u.id = i.owner_user_id
        '''
        if viewer.role != 'admin':
            query += ' WHERE i.owner_user_id = %s'
            parameters = (viewer.user_id,)
        query += ' ORDER BY u.email ASC, i.title ASC, i.id ASC'
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(cast(Any, query), parameters)
                rows = cur.fetchall()
        return [_row_to_item(cast(dict[str, object], row)).to_record() for row in rows]

    def get_item(self, *, item_id: str) -> StoredItem | None:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    '''
                    SELECT i.*, u.email AS owner_email
                    FROM items AS i
                    JOIN users AS u ON u.id = i.owner_user_id
                    WHERE i.id = %s
                    ''',
                    (item_id,),
                )
                row = cur.fetchone()
        return None if row is None else _row_to_item(cast(dict[str, object], row))

    def create_item(
        self,
        *,
        owner_user_id: str,
        title: str,
        state: ItemState,
        now: datetime,
    ) -> ItemRecord:
        item_id = str(uuid.uuid4())
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    '''
                    INSERT INTO items (id, owner_user_id, title, state, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING (
                        SELECT email
                        FROM users
                        WHERE id = %s
                    ) AS owner_email
                    ''',
                    (item_id, owner_user_id, title, state, now, now, owner_user_id),
                )
                row = cur.fetchone()
            conn.commit()
        if row is None:
            raise RuntimeError('create_item returned no row')
        return StoredItem(
            item_id=item_id,
            owner_user_id=owner_user_id,
            owner_email=str(row['owner_email']),
            title=title,
            state=normalize_state(state),
            created_at=now,
            updated_at=now,
        ).to_record()

    def update_item(
        self,
        *,
        item_id: str,
        title: str | None,
        state: ItemState | None,
        now: datetime,
    ) -> ItemRecord | None:
        item = self.get_item(item_id=item_id)
        if item is None:
            return None
        next_title = title if title is not None else item.title
        next_state = normalize_state(state) if state is not None else item.state
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    '''
                    UPDATE items
                    SET title = %s, state = %s, updated_at = %s
                    WHERE id = %s
                    RETURNING *
                    ''',
                    (next_title, next_state, now, item_id),
                )
                row = cur.fetchone()
            conn.commit()
        if row is None:
            return None
        stored = _row_to_item(
            {
                **cast(dict[str, object], row),
                'owner_email': item.owner_email,
            }
        )
        return stored.to_record()

    def delete_item(self, *, item_id: str) -> bool:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM items WHERE id = %s', (item_id,))
                deleted = cur.rowcount > 0
            conn.commit()
        return deleted


def build_default_store() -> WorkspaceStore:
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise RuntimeError('DATABASE_URL is required for default application startup.')
    return PostgresWorkspaceStore(database_url)


def read_workspace_state(database_url: str) -> WorkspaceStatePayload:
    with psycopg.connect(database_url) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute('SELECT * FROM users ORDER BY email ASC')
            user_rows = cur.fetchall()
            cur.execute(
                '''
                SELECT i.*, u.email AS owner_email
                FROM items AS i
                JOIN users AS u ON u.id = i.owner_user_id
                ORDER BY u.email ASC, i.title ASC, i.id ASC
                '''
            )
            item_rows = cur.fetchall()
            cur.execute('SELECT COUNT(*) AS session_count FROM sessions')
            session_count_row = cur.fetchone()
    users = [
        _row_to_user(cast(dict[str, object], row)).to_record().model_dump(mode='json')
        for row in user_rows
    ]
    items = [
        _row_to_item(cast(dict[str, object], row)).to_record().model_dump(mode='json')
        for row in item_rows
    ]
    session_count = 0 if session_count_row is None else int(session_count_row['session_count'])
    return {'users': users, 'items': items, 'session_count': session_count}


def purge_workspace_sessions(database_url: str) -> int:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM sessions')
            deleted = cur.rowcount
        conn.commit()
    return deleted
