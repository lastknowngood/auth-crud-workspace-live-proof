from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

Role = Literal['admin', 'member']
ItemState = Literal['open', 'done']


class UserRecord(BaseModel):
    user_id: str
    email: str
    role: Role
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    user: UserRecord
    expires_at: datetime


class ItemCreateRequest(BaseModel):
    title: str
    state: ItemState = 'open'


class ItemUpdateRequest(BaseModel):
    title: str | None = None
    state: ItemState | None = None


class ItemRecord(BaseModel):
    item_id: str
    owner_user_id: str
    owner_email: str
    title: str
    state: ItemState
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProofResetRecord(BaseModel):
    admin_user: UserRecord
    member_user: UserRecord
    admin_item: ItemRecord
    member_item: ItemRecord
    session_count: int


class HealthzRecord(BaseModel):
    status: str
    project: str
    store: str
    build_revision: str
    proof_mode: bool
    session_ttl_seconds: int


@dataclass(slots=True)
class StoredUser:
    user_id: str
    email: str
    role: Role
    password_hash: str
    created_at: datetime
    updated_at: datetime

    def to_record(self) -> UserRecord:
        return UserRecord(
            user_id=self.user_id,
            email=self.email,
            role=self.role,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


@dataclass(slots=True)
class StoredItem:
    item_id: str
    owner_user_id: str
    owner_email: str
    title: str
    state: ItemState
    created_at: datetime
    updated_at: datetime

    def to_record(self) -> ItemRecord:
        return ItemRecord(
            item_id=self.item_id,
            owner_user_id=self.owner_user_id,
            owner_email=self.owner_email,
            title=self.title,
            state=self.state,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


@dataclass(slots=True)
class StoredSession:
    token_hash: str
    user_id: str
    expires_at: datetime
    created_at: datetime

