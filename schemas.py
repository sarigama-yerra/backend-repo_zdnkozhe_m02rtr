"""
Database Schemas for Tenang.in

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
- User -> "user"
- Mood -> "mood"
- Assessment -> "assessment"
- Thought -> "thought"
- Exercise -> "exercise"
- Article -> "article"
- Reminder -> "reminder"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Core user and auth
class User(BaseModel):
    name: str = Field(..., min_length=1, max_length=80, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    phone: Optional[str] = Field(None, max_length=20, description="Phone number")
    password_hash: str = Field(..., description="Hashed password (bcrypt)")
    provider: Literal["password", "google"] = Field("password", description="Auth provider")
    avatar_url: Optional[str] = Field(None)
    preferences: dict = Field(default_factory=lambda: {"dark_mode": False, "reminders": True, "reduce_motion": False})

class Mood(BaseModel):
    user_id: str
    date: datetime
    mood_emoji: Literal["😊", "😐", "😟", "😣"]
    anxiety_score: int = Field(..., ge=1, le=10)
    triggers: List[str] = Field(default_factory=list)
    note: Optional[str] = Field(None, max_length=300)

class Assessment(BaseModel):
    user_id: str
    type: Literal["gad7"]
    answers: List[int] = Field(..., min_items=5, max_items=7)
    score: int = Field(..., ge=0, le=21)
    category: Literal["rendah", "sedang", "tinggi"]

class Thought(BaseModel):
    user_id: str
    situation: str = Field(..., max_length=500)
    automatic_thought: str = Field(..., max_length=500)
    emotion: str = Field(..., max_length=200)
    evidence_for: str = Field(..., max_length=800)
    evidence_against: str = Field(..., max_length=800)
    alternative_thought: str = Field(..., max_length=500)

class Exercise(BaseModel):
    user_id: str
    type: Literal["breathing"]
    duration_sec: int = Field(..., ge=30, le=900)
    completed_at: datetime

class Article(BaseModel):
    title: str
    slug: str
    summary: str
    content: str
    tags: List[str] = Field(default_factory=list)
    read_time_min: int = Field(..., ge=1, le=15)

class Reminder(BaseModel):
    user_id: str
    type: Literal["daily_checkin", "exercise"]
    schedule_iso: str
    channel: Literal["email", "push", "sms"] = "email"
    active: bool = True
