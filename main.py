import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import User, Mood, Assessment, Thought, Exercise, Article, Reminder

APP_NAME = "Tenang.in"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRES_MIN = 60 * 24  # 24h

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title=APP_NAME, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Auth Utilities ----------
class RegisterInput(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginInput(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(sub: str) -> str:
    payload = {
        "sub": sub,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN),
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_or_create_guest_user() -> dict:
    """Return a shared guest user document for passwordless/anonymous usage."""
    email = "guest@tenang.in"
    user = db["user"].find_one({"email": email})
    if not user:
        create_document(
            "user",
            User(
                name="Tamu",
                email=email,
                phone=None,
                password_hash=hash_password("guest"),
                provider="guest",
                avatar_url=None,
            ).model_dump(),
        )
        user = db["user"].find_one({"email": email})
    user = user or {"email": email, "name": "Tamu"}
    user["_id"] = str(user.get("_id", ""))
    return user


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """
    If Authorization Bearer token is provided and valid, return that user.
    Otherwise, fall back to a shared guest user so the app can be used tanpa login.
    """
    if not authorization:
        return get_or_create_guest_user()
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            return get_or_create_guest_user()
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        user = db["user"].find_one({"email": user_id})
        if not user:
            return get_or_create_guest_user()
        user["_id"] = str(user.get("_id"))
        return user
    except Exception:
        # Any token error => treat as guest instead of blocking
        return get_or_create_guest_user()


# ---------- Public Endpoints ----------
@app.get("/")
def root():
    return {"app": APP_NAME, "status": "ok"}

@app.get("/test")
def test_database():
    info = {
        "backend": "running",
        "database": "connected" if db is not None else "not_connected",
    }
    try:
        if db is not None:
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["error"] = str(e)
    return info


# ---------- Auth Routes (kept for compatibility, not required by UI) ----------
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterInput):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email sudah terdaftar")
    user_doc = User(
        name=payload.name,
        email=payload.email,
        phone=None,
        password_hash=hash_password(payload.password),
        provider="password",
        avatar_url=None,
    ).model_dump()
    create_document("user", user_doc)
    token = create_access_token(payload.email)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginInput):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Email atau password salah")
    token = create_access_token(payload.email)
    return TokenResponse(access_token=token)


# Placeholder for Google login
class GoogleAuthInput(BaseModel):
    id_token: str

@app.post("/auth/google", response_model=TokenResponse)
def login_google(_: GoogleAuthInput):
    email = "user.google@example.com"
    existing = db["user"].find_one({"email": email})
    if not existing:
        create_document(
            "user",
            User(
                name="Pengguna Google",
                email=email,
                phone=None,
                password_hash=hash_password("oauth"),
                provider="google",
                avatar_url=None,
            ).model_dump(),
        )
    token = create_access_token(email)
    return TokenResponse(access_token=token)


# ---------- Protected Models (now accept guest via get_current_user) ----------
class MoodInput(BaseModel):
    date: Optional[datetime] = None
    mood_emoji: str
    anxiety_score: int
    triggers: List[str] = []
    note: Optional[str] = None

@app.post("/moods")
def create_mood(payload: MoodInput, user=Depends(get_current_user)):
    doc = Mood(
        user_id=user["email"],
        date=payload.date or datetime.now(timezone.utc),
        mood_emoji=payload.mood_emoji,
        anxiety_score=payload.anxiety_score,
        triggers=payload.triggers,
        note=payload.note,
    ).model_dump()
    _id = create_document("mood", doc)
    return {"id": _id, "status": "saved"}


@app.get("/moods")
def list_moods(range: Optional[str] = None, user=Depends(get_current_user)):
    # Filter last 7 or 30 days
    q = {"user_id": user["email"]}
    if range == "week":
        since = datetime.now(timezone.utc) - timedelta(days=7)
        q["date"] = {"$gte": since}
    elif range == "month":
        since = datetime.now(timezone.utc) - timedelta(days=30)
        q["date"] = {"$gte": since}
    items = get_documents("mood", q)
    for it in items:
        it["_id"] = str(it.get("_id")) if "_id" in it else None
    return items


class GAD7Input(BaseModel):
    answers: List[int]

@app.post("/assessments/gad7")
def submit_gad7(payload: GAD7Input, user=Depends(get_current_user)):
    answers = payload.answers
    if len(answers) < 5 or len(answers) > 7 or any(a < 0 or a > 3 for a in answers):
        raise HTTPException(status_code=400, detail="Jawaban tidak valid")
    score = sum(answers)
    if score <= 4:
        category = "rendah"
        recommendation = "Skor kecemasanmu rendah. Tetap jaga rutinitas sehat dan lakukan check-in harian."
    elif score <= 9:
        category = "sedang"
        recommendation = "Kecemasan sedang. Coba latihan napas 3 menit dan jurnal singkat setelah aktivitas yang memicu."
    else:
        category = "tinggi"
        recommendation = "Kecemasan tinggi. Pertimbangkan berbicara dengan profesional. Kita bisa mulai dengan latihan napas dan grounding 5-4-3-2-1."
    doc = Assessment(user_id=user["email"], type="gad7", answers=answers, score=score, category=category).model_dump()
    create_document("assessment", doc)
    return {"score": score, "category": category, "recommendation": recommendation}


class ThoughtInput(BaseModel):
    situation: str
    automatic_thought: str
    emotion: str
    evidence_for: str
    evidence_against: str
    alternative_thought: str

@app.post("/thoughts")
def create_thought(payload: ThoughtInput, user=Depends(get_current_user)):
    doc = Thought(user_id=user["email"], **payload.model_dump()).model_dump()
    _id = create_document("thought", doc)
    return {"id": _id, "status": "saved"}

@app.get("/thoughts")
def list_thoughts(limit: int = 20, user=Depends(get_current_user)):
    items = get_documents("thought", {"user_id": user["email"]}, limit)
    for it in items:
        it["_id"] = str(it["_id"]) if "_id" in it else None
    return items


class ExerciseInput(BaseModel):
    duration_sec: int

@app.post("/exercises/breathing")
def log_breathing(payload: ExerciseInput, user=Depends(get_current_user)):
    doc = Exercise(user_id=user["email"], type="breathing", duration_sec=payload.duration_sec, completed_at=datetime.now(timezone.utc)).model_dump()
    _id = create_document("exercise", doc)
    return {"id": _id, "status": "logged"}

@app.get("/exercises/streak")
def get_streak(user=Depends(get_current_user)):
    # Simple streak based on daily breathing logs
    items = get_documents("exercise", {"user_id": user["email"], "type": "breathing"})
    dates = sorted({str(it.get("completed_at", ""))[:10] for it in items if it.get("completed_at")})
    return {"days": len(dates)}


# Articles (public for MVP)
@app.get("/articles")
def list_articles(tag: Optional[str] = None):
    q = {}
    if tag:
        q = {"tags": {"$in": [tag]}}
    items = get_documents("article", q)
    for it in items:
        it["_id"] = str(it.get("_id"))
    return items

@app.get("/articles/{slug}")
def get_article(slug: str):
    item = db["article"].find_one({"slug": slug})
    if not item:
        raise HTTPException(status_code=404, detail="Artikel tidak ditemukan")
    item["_id"] = str(item["_id"])
    return item


# Safety resources
@app.get("/safety/resources")
def safety_resources():
    return {
        "contacts": [
            {"label": "Orang Kepercayaan", "action": "phone", "value": "+62-812-xxxx-xxxx"},
            {"label": "Layanan Konseling Kampus", "action": "link", "value": "https://contoh-konseling-kampus.id"},
            {"label": "Hotline Kesehatan Jiwa (Kemenkes)", "action": "phone", "value": "1500-454"},
        ]
    }


# Simple preferences
class PrefInput(BaseModel):
    dark_mode: Optional[bool] = None
    reminders: Optional[bool] = None
    reduce_motion: Optional[bool] = None

@app.patch("/me/preferences")
def update_preferences(payload: PrefInput, user=Depends(get_current_user)):
    prefs = user.get("preferences", {})
    for k, v in payload.model_dump(exclude_none=True).items():
        prefs[k] = v
    db["user"].update_one({"email": user["email"]}, {"$set": {"preferences": prefs}})
    return {"preferences": prefs}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
