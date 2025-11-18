"""
Database Schemas for the Salon App

Each Pydantic model represents a collection in MongoDB. The collection
name is the lowercase of the class name.

- User -> "user"
- Reservation -> "reservation"
"""
from __future__ import annotations

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import date, time, datetime

class User(BaseModel):
    """Users collection schema"""
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: Optional[str] = Field(None, description="BCrypt hash for email/password users")
    provider: Literal["password", "google"] = Field("password", description="Auth provider")
    role: Literal["user", "admin"] = Field("user", description="Role")
    picture: Optional[str] = Field(None, description="Avatar URL")
    is_active: bool = Field(True, description="Whether user is active")

class Reservation(BaseModel):
    """Reservations collection schema"""
    user_id: str = Field(..., description="User id as string")
    date: date = Field(..., description="Reservation date (YYYY-MM-DD)")
    time: time = Field(..., description="Reservation start time (HH:MM)")
    duration_minutes: int = Field(30, ge=30, le=240, description="Duration in minutes")
    status: Literal["confirmada", "cancelada", "modificada"] = Field("confirmada")
    notes: Optional[str] = Field(None, description="Optional notes")
    service: Optional[str] = Field(None, description="Service type")

# Expose minimal schema endpoint expectations (used by tooling)
SCHEMAS_INFO = {
    "user": User.model_json_schema(),
    "reservation": Reservation.model_json_schema(),
}
