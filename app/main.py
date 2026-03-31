import hmac
import os
from collections.abc import Callable
from hashlib import sha256
from http import HTTPStatus

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from .build_info import get_build_revision
from .models import (
    HealthzRecord,
    ItemCreateRequest,
    ItemRecord,
    ItemUpdateRequest,
    LoginRequest,
    LoginResponse,
    ProofResetRecord,
    UserRecord,
)
from .store import StoredUser, WorkspaceStore, build_default_store, utcnow

MARKER = 'AUTH-CRUD-WORKSPACE-LIVE-PROOF OK'
SESSION_COOKIE_NAME = 'auth_workspace_session'
PROJECT_NAME = 'auth-crud-workspace-live-proof'


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def parse_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    return int(value.strip())


def normalize_title(value: str) -> str:
    title = value.strip()
    if not title:
        raise HTTPException(status_code=422, detail='title_required')
    return title


def select_session_secret(explicit_value: str | None = None) -> str:
    selected = explicit_value or os.getenv('SESSION_SECRET')
    if not selected:
        raise RuntimeError('SESSION_SECRET is required for application startup.')
    return selected


def sign_session_token(raw_token: str, session_secret: str) -> str:
    return hmac.new(
        session_secret.encode('utf-8'),
        raw_token.encode('utf-8'),
        sha256,
    ).hexdigest()


def encode_session_cookie(raw_token: str, session_secret: str) -> str:
    return f'{raw_token}.{sign_session_token(raw_token, session_secret)}'


def decode_session_cookie(cookie_value: str, session_secret: str) -> str | None:
    if '.' not in cookie_value:
        return None
    raw_token, signature = cookie_value.rsplit('.', 1)
    expected_signature = sign_session_token(raw_token, session_secret)
    if not hmac.compare_digest(signature, expected_signature):
        return None
    return raw_token


def is_https_request(request: Request) -> bool:
    forwarded_proto = request.headers.get('x-forwarded-proto')
    if forwarded_proto:
        return forwarded_proto.split(',', 1)[0].strip().lower() == 'https'
    return request.url.scheme.lower() == 'https'


def create_app(
    *,
    store_factory: Callable[[], WorkspaceStore] | None = None,
    proof_mode: bool | None = None,
    session_secret: str | None = None,
    session_ttl_seconds: int | None = None,
    admin_bootstrap_password: str | None = None,
    member_bootstrap_password: str | None = None,
) -> FastAPI:
    store = (store_factory or build_default_store)()
    selected_proof_mode = proof_mode if proof_mode is not None else parse_bool(
        os.getenv('PROOF_MODE'),
        default=False,
    )
    selected_session_secret = select_session_secret(session_secret)
    selected_session_ttl_seconds = (
        session_ttl_seconds
        if session_ttl_seconds is not None
        else parse_int(os.getenv('SESSION_TTL_SECONDS'), default=3600)
    )
    selected_admin_password = admin_bootstrap_password or os.getenv('ADMIN_BOOTSTRAP_PASSWORD')
    selected_member_password = member_bootstrap_password or os.getenv('MEMBER_BOOTSTRAP_PASSWORD')
    if not selected_admin_password:
        raise RuntimeError('ADMIN_BOOTSTRAP_PASSWORD is required for application startup.')
    if not selected_member_password:
        raise RuntimeError('MEMBER_BOOTSTRAP_PASSWORD is required for application startup.')
    build_revision = get_build_revision()

    app = FastAPI(title=PROJECT_NAME)

    @app.middleware('http')
    async def add_anti_indexing_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers['X-Robots-Tag'] = (
            'noindex, nofollow, noarchive, noimageindex, nosnippet'
        )
        return response

    def delete_session_cookie(response: Response) -> None:
        response.delete_cookie(
            SESSION_COOKIE_NAME,
            path='/',
            httponly=True,
            samesite='lax',
        )

    def get_current_user(request: Request) -> StoredUser:
        cookie_value = request.cookies.get(SESSION_COOKIE_NAME)
        if not cookie_value:
            raise HTTPException(status_code=401, detail='auth_required')
        raw_token = decode_session_cookie(cookie_value, selected_session_secret)
        if raw_token is None:
            raise HTTPException(status_code=401, detail='invalid_session')
        user = store.get_user_for_session(raw_token=raw_token, now=utcnow())
        if user is None:
            raise HTTPException(status_code=401, detail='auth_required')
        request.state.raw_session_token = raw_token
        request.state.current_user = user
        return user

    def get_admin_user(request: Request) -> StoredUser:
        user = get_current_user(request)
        if user.role != 'admin':
            raise HTTPException(status_code=403, detail='admin_required')
        return user

    def ensure_item_access(item: ItemRecord, viewer: StoredUser) -> None:
        if viewer.role == 'admin':
            return
        if item.owner_user_id != viewer.user_id:
            raise HTTPException(status_code=403, detail='item_forbidden')

    @app.get('/healthz')
    def healthz() -> HealthzRecord:
        return HealthzRecord(
            status='ok',
            project=PROJECT_NAME,
            store=store.__class__.__name__,
            build_revision=build_revision,
            proof_mode=selected_proof_mode,
            session_ttl_seconds=selected_session_ttl_seconds,
        )

    @app.get('/robots.txt', response_class=PlainTextResponse)
    def robots_txt() -> PlainTextResponse:
        return PlainTextResponse('User-agent: *\nDisallow: /\n')

    @app.get('/', response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(
            f'''<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex,nofollow,noarchive,noimageindex,nosnippet">
    <title>{PROJECT_NAME}</title>
  </head>
  <body>
    <main>
      <h1>{MARKER}</h1>
      <p>Generic authenticated stateful CRUD workspace proof.</p>
      <p>Proof mode: {str(selected_proof_mode).lower()}</p>
      <p>Session model: DB-backed, cookie-authenticated.</p>
    </main>
  </body>
</html>'''
        )

    @app.post('/proof/reset', response_model=ProofResetRecord)
    def proof_reset() -> ProofResetRecord:
        if not selected_proof_mode:
            raise HTTPException(status_code=403, detail='proof_mode_disabled')
        return store.reset_proof_state(
            admin_password=selected_admin_password,
            member_password=selected_member_password,
        )

    @app.post('/auth/login', response_model=LoginResponse)
    def login(payload: LoginRequest, request: Request) -> JSONResponse:
        user = store.authenticate_user(email=payload.email, password=payload.password)
        if user is None:
            raise HTTPException(status_code=401, detail='invalid_credentials')
        raw_token, expires_at = store.create_session(
            user_id=user.user_id,
            now=utcnow(),
            ttl_seconds=selected_session_ttl_seconds,
        )
        body = LoginResponse(user=user.to_record(), expires_at=expires_at).model_dump(mode='json')
        response = JSONResponse(status_code=HTTPStatus.OK, content=body)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            encode_session_cookie(raw_token, selected_session_secret),
            max_age=selected_session_ttl_seconds,
            expires=selected_session_ttl_seconds,
            httponly=True,
            samesite='lax',
            secure=is_https_request(request),
            path='/',
        )
        return response

    @app.post('/auth/logout', status_code=204)
    def logout(request: Request) -> Response:
        cookie_value = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie_value:
            raw_token = decode_session_cookie(cookie_value, selected_session_secret)
            if raw_token is not None:
                store.delete_session(raw_token=raw_token)
        response = Response(status_code=204)
        delete_session_cookie(response)
        return response

    @app.get('/auth/me', response_model=UserRecord)
    def auth_me(request: Request) -> UserRecord:
        return get_current_user(request).to_record()

    @app.get('/admin/users', response_model=list[UserRecord])
    def admin_users(request: Request) -> list[UserRecord]:
        get_admin_user(request)
        return store.list_users()

    @app.get('/items', response_model=list[ItemRecord])
    def list_items(request: Request) -> list[ItemRecord]:
        viewer = get_current_user(request)
        return store.list_items_for_user(viewer=viewer)

    @app.post('/items', response_model=ItemRecord, status_code=201)
    def create_item(payload: ItemCreateRequest, request: Request) -> ItemRecord:
        viewer = get_current_user(request)
        return store.create_item(
            owner_user_id=viewer.user_id,
            title=normalize_title(payload.title),
            state=payload.state,
            now=utcnow(),
        )

    @app.patch('/items/{item_id}', response_model=ItemRecord)
    def patch_item(item_id: str, payload: ItemUpdateRequest, request: Request) -> ItemRecord:
        viewer = get_current_user(request)
        item = store.get_item(item_id=item_id)
        if item is None:
            raise HTTPException(status_code=404, detail='item_not_found')
        ensure_item_access(item.to_record(), viewer)
        if payload.title is None and payload.state is None:
            raise HTTPException(status_code=422, detail='item_update_required')
        updated = store.update_item(
            item_id=item_id,
            title=normalize_title(payload.title) if payload.title is not None else None,
            state=payload.state,
            now=utcnow(),
        )
        if updated is None:
            raise HTTPException(status_code=404, detail='item_not_found')
        return updated

    @app.delete('/items/{item_id}', status_code=204)
    def delete_item(item_id: str, request: Request) -> Response:
        viewer = get_current_user(request)
        item = store.get_item(item_id=item_id)
        if item is None:
            raise HTTPException(status_code=404, detail='item_not_found')
        ensure_item_access(item.to_record(), viewer)
        deleted = store.delete_item(item_id=item_id)
        if not deleted:
            raise HTTPException(status_code=404, detail='item_not_found')
        return Response(status_code=204)

    return app

