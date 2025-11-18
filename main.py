import os
from datetime import datetime, timedelta, time as dtime, date as ddate
from typing import List, Optional, Literal

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Reservation as ReservationSchema

# Environment
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Auth utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# FastAPI app
app = FastAPI(title="Salon Booking API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----- Helpers -----

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(email: str) -> Optional[dict]:
    user = db["user"].find_one({"email": email})
    if user:
        user["id"] = str(user.get("_id"))
    return user


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    user["id"] = str(user["_id"])  # add id string
    return user


def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


# ----- Models -----
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class GoogleLoginRequest(BaseModel):
    token: str  # id_token from Google (client-side)


class ReservationCreate(BaseModel):
    date: ddate
    time: dtime
    duration_minutes: int = 30
    service: Optional[str] = None
    notes: Optional[str] = None


class ReservationUpdate(BaseModel):
    date: Optional[ddate] = None
    time: Optional[dtime] = None
    duration_minutes: Optional[int] = None
    status: Optional[Literal["confirmada", "cancelada", "modificada"]] = None
    service: Optional[str] = None
    notes: Optional[str] = None


# ----- Public Endpoints -----
@app.get("/")
def root():
    return {"message": "Salon Booking API running"}


@app.get("/schema")
def schema_info():
    # small helper for tooling
    return {"collections": ["user", "reservation"]}


# Auth: Email + Password
@app.post("/auth/register", response_model=Token)
def register(data: RegisterRequest):
    if get_user_by_email(data.email):
        raise HTTPException(400, "Email already registered")
    user_doc = UserSchema(
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password),
        provider="password",
        role="user",
    ).model_dump()
    inserted_id = db["user"].insert_one(user_doc).inserted_id
    access_token = create_access_token({"sub": str(inserted_id)})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not user.get("password_hash"):
        raise HTTPException(400, "Invalid credentials")
    if not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(400, "Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": token, "token_type": "bearer"}


# Google Login (simplified): accept id_token and upsert user
# In production you must verify the token with Google certs.
@app.post("/auth/google", response_model=Token)
def google_login(payload: GoogleLoginRequest):
    # For this environment, we'll treat token as email:name concatenation for demo purposes.
    # e.g., token = "user@example.com|John Doe"
    try:
        email, name = payload.token.split("|", 1)
    except Exception:
        raise HTTPException(400, "Invalid Google token format")

    user = get_user_by_email(email)
    if not user:
        user_doc = UserSchema(
            name=name,
            email=email,
            provider="google",
            role="user",
        ).model_dump()
        inserted_id = db["user"].insert_one(user_doc).inserted_id
        user_id = str(inserted_id)
    else:
        user_id = str(user["_id"]) if isinstance(user.get("_id"), ObjectId) else user.get("id")

    token = create_access_token({"sub": user_id})
    return {"access_token": token, "token_type": "bearer"}


# Profile
@app.get("/me")
def me(user=Depends(get_current_user)):
    return {
        "id": str(user["_id"]),
        "name": user.get("name"),
        "email": user.get("email"),
        "role": user.get("role", "user"),
        "picture": user.get("picture"),
    }


# ----- Reservations -----
BUSINESS_DAYS = {0, 1, 2, 3, 4, 5}  # Monday-Saturday
OPEN_TIME = dtime(10, 0)
CLOSE_TIME = dtime(20, 0)
SLOT_MINUTES = 30


def overlaps(start_a: datetime, duration_a: int, start_b: datetime, duration_b: int) -> bool:
    end_a = start_a + timedelta(minutes=duration_a)
    end_b = start_b + timedelta(minutes=duration_b)
    return max(start_a, start_b) < min(end_a, end_b)


def is_within_business_hours(dt: datetime, duration_minutes: int) -> bool:
    if dt.weekday() not in BUSINESS_DAYS:
        return False
    start_ok = OPEN_TIME <= dt.time() <= CLOSE_TIME
    end_ok = (dt + timedelta(minutes=duration_minutes)).time() <= CLOSE_TIME
    return start_ok and end_ok


@app.get("/reservations/available")
def available(date_str: str):
    target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    # Generate slots from 10:00 to 20:00 step 30
    slots: List[str] = []
    current = datetime.combine(target_date, OPEN_TIME)
    end_day = datetime.combine(target_date, CLOSE_TIME)
    while current <= end_day - timedelta(minutes=SLOT_MINUTES):
        slots.append(current.strftime("%H:%M"))
        current += timedelta(minutes=SLOT_MINUTES)

    # Remove occupied
    day_res = list(db["reservation"].find({"date": target_date.isoformat()}))
    occupied = set(r["time"] for r in day_res)
    free = [s for s in slots if s not in occupied]
    return {"date": target_date.isoformat(), "available": free}


@app.post("/reservations", status_code=201)
def create_reservation(data: ReservationCreate, user=Depends(get_current_user)):
    start_dt = datetime.combine(data.date, data.time)
    if data.duration_minutes != SLOT_MINUTES:
        raise HTTPException(400, "Solo se permiten citas de 30 minutos")
    if not is_within_business_hours(start_dt, data.duration_minutes):
        raise HTTPException(400, "Fuera de horario laboral")

    # prevent overlaps on same date/time
    exists = db["reservation"].find_one({
        "date": data.date.isoformat(),
        "time": data.time.strftime("%H:%M"),
        "status": {"$ne": "cancelada"}
    })
    if exists:
        raise HTTPException(400, "Horario no disponible")

    doc = ReservationSchema(
        user_id=str(user["_id"]),
        date=data.date,
        time=data.time,
        duration_minutes=data.duration_minutes,
        status="confirmada",
        service=data.service,
        notes=data.notes,
    ).model_dump()
    # normalize for Mongo
    doc["date"] = data.date.isoformat()
    doc["time"] = data.time.strftime("%H:%M")

    inserted = db["reservation"].insert_one(doc)
    return {"id": str(inserted.inserted_id), "message": "Reserva confirmada"}


@app.get("/reservations/mine")
def my_reservations(user=Depends(get_current_user)):
    res = list(db["reservation"].find({"user_id": str(user["_id"])}, sort=[("date", 1), ("time", 1)]))
    for r in res:
        r["id"] = str(r.pop("_id"))
    return res


# Admin endpoints
@app.get("/admin/reservations")
def admin_list_reservations(user=Depends(require_admin)):
    res = list(db["reservation"].find({}, sort=[("date", 1), ("time", 1)]))
    for r in res:
        r["id"] = str(r.pop("_id"))
    return res


@app.patch("/admin/reservations/{res_id}")
def admin_update_reservation(res_id: str, data: ReservationUpdate, user=Depends(require_admin)):
    update = {k: v for k, v in data.model_dump(exclude_unset=True).items()}
    if "date" in update and isinstance(update["date"], ddate):
        update["date"] = update["date"].isoformat()
    if "time" in update and isinstance(update["time"], dtime):
        update["time"] = update["time"].strftime("%H:%M")

    # If changing time/date, ensure no conflict
    existing = db["reservation"].find_one({"_id": ObjectId(res_id)})
    if not existing:
        raise HTTPException(404, "Reserva no encontrada")

    new_date = update.get("date", existing.get("date"))
    new_time = update.get("time", existing.get("time"))
    if new_date and new_time:
        conflict = db["reservation"].find_one({
            "_id": {"$ne": ObjectId(res_id)},
            "date": new_date,
            "time": new_time,
            "status": {"$ne": "cancelada"}
        })
        if conflict:
            raise HTTPException(400, "El horario elegido ya está ocupado")

    if update:
        db["reservation"].update_one({"_id": ObjectId(res_id)}, {"$set": update})
    return {"message": "Reserva actualizada"}


@app.delete("/admin/reservations/{res_id}")
def admin_cancel_reservation(res_id: str, user=Depends(require_admin)):
    result = db["reservation"].update_one({"_id": ObjectId(res_id)}, {"$set": {"status": "cancelada"}})
    if result.matched_count == 0:
        raise HTTPException(404, "Reserva no encontrada")
    return {"message": "Reserva cancelada"}


@app.get("/admin/users")
def admin_list_users(user=Depends(require_admin)):
    users = list(db["user"].find({}, sort=[("name", 1)]))
    for u in users:
        u["id"] = str(u.pop("_id"))
        u.pop("password_hash", None)
    return users


# Utility endpoints for availability checks
@app.get("/reservations/day/{date_str}")
def reservations_on_day(date_str: str):
    res = list(db["reservation"].find({"date": date_str}))
    for r in res:
        r["id"] = str(r.pop("_id"))
    return res


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
