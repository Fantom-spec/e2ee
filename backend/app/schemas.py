"""Request/response models. Requests forbid unknown fields; validators reuse
the framework-independent rules in validation.py."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import validation


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Request):
    # Field max_length caps the size before our (stricter) validators run.
    username: str = Field(max_length=64)
    display_name: str = Field(max_length=128)
    password: str = Field(max_length=256)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        return validation.normalize_username(v)

    @field_validator("display_name")
    @classmethod
    def _display_name(cls, v: str) -> str:
        return validation.validate_display_name(v)

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return validation.validate_password(v)


class LoginRequest(_Request):
    # No complexity rules at login: a wrong value is simply "invalid credentials".
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class UserOut(BaseModel):
    id: str
    username: str
    display_name: str


class LoginResponse(BaseModel):
    token: str
    expires_at: int
    user: UserOut


class TicketResponse(BaseModel):
    ticket: str
    expires_in: int


# --- key directory (Stage 3) -------------------------------------------------

class SignedPreKeyModel(_Request):
    id: int
    public: str = Field(max_length=128)
    signature: str = Field(max_length=160)

    @field_validator("id")
    @classmethod
    def _id(cls, v: int) -> int:
        return validation.validate_key_id(v, "signed prekey id")

    @field_validator("public")
    @classmethod
    def _public(cls, v: str) -> str:
        return validation.validate_public_key(v, "signed prekey")

    @field_validator("signature")
    @classmethod
    def _signature(cls, v: str) -> str:
        return validation.validate_signature(v, "signed prekey signature")


class OneTimePreKeyModel(_Request):
    id: int
    public: str = Field(max_length=128)

    @field_validator("id")
    @classmethod
    def _id(cls, v: int) -> int:
        return validation.validate_key_id(v, "one-time prekey id")

    @field_validator("public")
    @classmethod
    def _public(cls, v: str) -> str:
        return validation.validate_public_key(v, "one-time prekey")


class KeyUploadRequest(_Request):
    registration_id: int = Field(ge=0, le=2**31 - 1)
    identity_public: str = Field(max_length=128)
    signed_prekey: SignedPreKeyModel
    one_time_prekeys: list[OneTimePreKeyModel] = Field(default_factory=list, max_length=100)

    @field_validator("identity_public")
    @classmethod
    def _identity(cls, v: str) -> str:
        return validation.validate_public_key(v, "identity key")


class PublishKeysResponse(BaseModel):
    identity_changed: bool
    key_version: int
    one_time_prekeys_remaining: int


class KeyStatusResponse(BaseModel):
    has_keys: bool
    key_version: int | None
    one_time_prekeys_remaining: int


class SignedPreKeyOut(BaseModel):
    id: int
    public: str
    signature: str


class OneTimePreKeyOut(BaseModel):
    id: int
    public: str


class BundleOut(BaseModel):
    user_id: str
    registration_id: int
    identity_public: str
    key_version: int
    signed_prekey: SignedPreKeyOut
    one_time_prekey: OneTimePreKeyOut | None


class IdentityOut(BaseModel):
    user_id: str
    identity_public: str
    key_version: int
    updated_at: int
