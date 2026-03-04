"""SecureNote — Main FastAPI application.

A secure note-taking API demonstrating authentication best practices:
  - Argon2id password hashing (ch02)
  - JWT RS256 token management (ch09)
  - OAuth2 Authorization Code + PKCE (ch07)
  - OIDC third-party login (ch08)
  - TOTP multi-factor authentication (ch10)
  - AES-256-GCM encrypted note storage (ch02)
  - FastAPI security integration (ch25)
"""

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.password import hash_password, verify_password, needs_rehash
from auth.jwt_handler import create_token_pair, decode_token, create_access_token
from auth.totp import (
    generate_totp_secret, get_totp_uri, generate_qr_code_base64,
    verify_totp_code, generate_recovery_codes, hash_recovery_codes,
    verify_recovery_code,
)
from auth.oauth2 import (
    PROVIDERS, build_authorization_url, exchange_code_for_tokens,
    fetch_userinfo, generate_code_verifier, generate_code_challenge,
    generate_state, generate_nonce,
)
from auth.dependencies import get_current_active_user, require_mfa_verified
from crypto.encryption import encrypt_note, decrypt_note
from models.database import init_db, get_db
from models.user import User, RevokedToken
from models.note import Note
from config import settings


# ── Lifespan ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="SecureNote API",
    description="Secure note-taking API — demonstrates authentication & encryption best practices",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Schemas ──────────────────────────

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    mfa_required: bool = False

class RefreshRequest(BaseModel):
    refresh_token: str

class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code: str  # base64 PNG
    recovery_codes: list[str]

class TOTPVerifyRequest(BaseModel):
    code: str

class NoteCreate(BaseModel):
    title: str
    content: str

class NoteUpdate(BaseModel):
    title: str | None = None
    content: str | None = None

class NoteResponse(BaseModel):
    id: str
    title: str
    content: str
    created_at: datetime
    updated_at: datetime


# ── Health Check ────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "SecureNote"}


# ── Auth: Register ──────────────────────────────────────

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new user with Argon2id password hashing (ch02)."""
    # Check uniqueness
    result = await db.execute(
        select(User).where((User.username == req.username) | (User.email == req.email))
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user = User(
        username=req.username,
        email=req.email,
        hashed_password=hash_password(req.password),
        is_verified=True,  # skip email verification for demo
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {"id": user.id, "username": user.username, "message": "Registration successful"}


# ── Auth: Login ─────────────────────────────────────────

@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate with username/password, return JWT tokens (ch09).

    If MFA is enabled, returns a limited token that requires TOTP verification.
    """
    result = await db.execute(select(User).where(User.username == req.username))
    user = result.scalar_one_or_none()

    if not user or not user.hashed_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Transparent hash upgrade (ch02: parameter migration)
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(req.password)
        await db.commit()

    # Check if MFA is required
    if user.totp_enabled:
        # Issue a limited token that only allows MFA verification
        limited_token = create_access_token(user.id, {"mfa_verified": False})
        return TokenResponse(
            access_token=limited_token,
            refresh_token="",
            expires_in=300,  # 5 min to complete MFA
            mfa_required=True,
        )

    tokens = create_token_pair(user.id)
    return TokenResponse(**tokens, mfa_required=False)


# ── Auth: MFA Verify ────────────────────────────────────

@app.post("/auth/mfa/verify", response_model=TokenResponse)
async def mfa_verify(
    req: TOTPVerifyRequest,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and upgrade to full access token (ch10)."""
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not configured")

    if not verify_totp_code(user.totp_secret, req.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    tokens = create_token_pair(user.id, {"mfa_verified": True})
    return TokenResponse(**tokens, mfa_required=False)


# ── Auth: Token Refresh ─────────────────────────────────

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a refresh token for a new token pair (ch09: token rotation)."""
    try:
        payload = decode_token(req.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    # Revoke the old refresh token (rotation)
    jti = payload.get("jti")
    if jti:
        revoked = RevokedToken(
            jti=jti,
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )
        db.add(revoked)
        await db.commit()

    user_id = payload["sub"]
    tokens = create_token_pair(user_id)
    return TokenResponse(**tokens, mfa_required=False)


# ── Auth: Logout (Token Revocation) ─────────────────────

@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current access token (ch09: token blacklist)."""
    # The token JTI is extracted in the dependency; here we'd add it to blacklist
    # For simplicity, this endpoint just confirms logout
    return None


# ── MFA: Setup TOTP ─────────────────────────────────────

@app.post("/auth/mfa/setup", response_model=TOTPSetupResponse)
async def mfa_setup(
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret and QR code for authenticator app setup (ch10)."""
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="MFA already enabled")

    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.username)
    qr_base64 = generate_qr_code_base64(uri)
    recovery = generate_recovery_codes()

    # Store secret and hashed recovery codes
    user.totp_secret = secret
    user.recovery_codes = json.dumps(hash_recovery_codes(recovery))
    await db.commit()

    return TOTPSetupResponse(
        secret=secret,
        qr_code=qr_base64,
        recovery_codes=recovery,  # shown once, then discarded
    )


@app.post("/auth/mfa/enable")
async def mfa_enable(
    req: TOTPVerifyRequest,
    user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm MFA setup by verifying the first TOTP code (ch10)."""
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /auth/mfa/setup first")

    if not verify_totp_code(user.totp_secret, req.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code — MFA not enabled")

    user.totp_enabled = True
    await db.commit()
    return {"message": "MFA enabled successfully"}


# ── OAuth2 / OIDC ──────────────────────────────────────

# In-memory state store (use Redis in production)
_oauth_states: dict[str, dict] = {}


@app.get("/auth/oauth/{provider}/authorize")
async def oauth_authorize(provider: str):
    """Start OAuth2 Authorization Code + PKCE flow (ch07, ch08)."""
    if provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    prov = PROVIDERS[provider]
    state = generate_state()
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    nonce = generate_nonce()

    _oauth_states[state] = {"provider": provider, "verifier": verifier, "nonce": nonce}

    url = build_authorization_url(prov, state, challenge, nonce)
    return {"authorization_url": url}


@app.get("/auth/callback")
async def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    """Handle OAuth2 callback — exchange code for tokens (ch07, ch08)."""
    if state not in _oauth_states:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    ctx = _oauth_states.pop(state)
    provider = PROVIDERS[ctx["provider"]]

    # Exchange authorization code for tokens
    token_data = await exchange_code_for_tokens(provider, code, ctx["verifier"])
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Token exchange failed")

    # Fetch user info from provider
    userinfo = await fetch_userinfo(provider, access_token)

    # Find or create user
    email = userinfo.get("email")
    sub = str(userinfo.get("sub") or userinfo.get("id"))

    result = await db.execute(
        select(User).where(User.oauth_provider == ctx["provider"], User.oauth_sub == sub)
    )
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            username=userinfo.get("login") or userinfo.get("name") or email.split("@")[0],
            email=email,
            oauth_provider=ctx["provider"],
            oauth_sub=sub,
            is_verified=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    tokens = create_token_pair(user.id)
    return TokenResponse(**tokens, mfa_required=False)


# ── Notes CRUD (encrypted) ─────────────────────────────

@app.post("/notes", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    req: NoteCreate,
    user: User = Depends(require_mfa_verified),
    db: AsyncSession = Depends(get_db),
):
    """Create a new encrypted note (ch02: AES-256-GCM)."""
    ciphertext, nonce, tag = encrypt_note(req.content, user.id)

    note = Note(
        title=req.title,
        encrypted_content=ciphertext,
        nonce=nonce,
        tag=tag,
        owner_id=user.id,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    return NoteResponse(
        id=note.id,
        title=note.title,
        content=req.content,  # return plaintext to creator
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@app.get("/notes", response_model=list[NoteResponse])
async def list_notes(
    user: User = Depends(require_mfa_verified),
    db: AsyncSession = Depends(get_db),
):
    """List all notes for the current user (decrypted)."""
    result = await db.execute(
        select(Note).where(Note.owner_id == user.id).order_by(Note.updated_at.desc())
    )
    notes = result.scalars().all()

    return [
        NoteResponse(
            id=n.id,
            title=n.title,
            content=decrypt_note(n.encrypted_content, n.nonce, n.tag, user.id),
            created_at=n.created_at,
            updated_at=n.updated_at,
        )
        for n in notes
    ]


@app.get("/notes/{note_id}", response_model=NoteResponse)
async def get_note(
    note_id: str,
    user: User = Depends(require_mfa_verified),
    db: AsyncSession = Depends(get_db),
):
    """Get a single note by ID (decrypted)."""
    result = await db.execute(
        select(Note).where(Note.id == note_id, Note.owner_id == user.id)
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    return NoteResponse(
        id=note.id,
        title=note.title,
        content=decrypt_note(note.encrypted_content, note.nonce, note.tag, user.id),
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@app.put("/notes/{note_id}", response_model=NoteResponse)
async def update_note(
    note_id: str,
    req: NoteUpdate,
    user: User = Depends(require_mfa_verified),
    db: AsyncSession = Depends(get_db),
):
    """Update a note (re-encrypts content if changed)."""
    result = await db.execute(
        select(Note).where(Note.id == note_id, Note.owner_id == user.id)
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    if req.title is not None:
        note.title = req.title

    content = req.content
    if content is not None:
        ciphertext, nonce, tag = encrypt_note(content, user.id)
        note.encrypted_content = ciphertext
        note.nonce = nonce
        note.tag = tag
    else:
        content = decrypt_note(note.encrypted_content, note.nonce, note.tag, user.id)

    await db.commit()
    await db.refresh(note)

    return NoteResponse(
        id=note.id,
        title=note.title,
        content=content,
        created_at=note.created_at,
        updated_at=note.updated_at,
    )


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    note_id: str,
    user: User = Depends(require_mfa_verified),
    db: AsyncSession = Depends(get_db),
):
    """Delete a note."""
    result = await db.execute(
        select(Note).where(Note.id == note_id, Note.owner_id == user.id)
    )
    note = result.scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    await db.delete(note)
    await db.commit()
