"""
Backend REST API con Supabase
Soporta SQLite local (desarrollo) y Supabase (producción)
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import jwt
import bcrypt
from datetime import datetime, timedelta
import json
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Detectar si usar Supabase o SQLite
USE_SUPABASE = os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_KEY")

if USE_SUPABASE:
    from supabase_config import init_supabase, SupabaseDB
    print("🟢 Usando SUPABASE (Base de datos en la nube)")
    init_supabase()
else:
    import sqlite3
    print("🟡 Usando SQLite local")
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logistics.db")

app = FastAPI(title="VaneLux/Conexaship API", version="2.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración JWT
SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer()

# ==================== MODELOS ====================
class LoginRequest(BaseModel):
    username: str
    password: str
    app_name: Optional[str] = None  # "vanelux" o "conexaship"

class RefreshRequest(BaseModel):
    refresh_token: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str
    roles: List[str] = ["worker"]
    allowed_apps: List[str] = ["vanelux", "conexaship"]

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    roles: List[str]
    allowed_apps: List[str]
    status: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    user: UserResponse

class BookingCreate(BaseModel):
    pickup_address: str
    pickup_lat: Optional[float] = None
    pickup_lng: Optional[float] = None
    destination_address: str
    destination_lat: Optional[float] = None
    destination_lng: Optional[float] = None
    pickup_time: str
    vehicle_name: Optional[str] = None
    passengers: int = 1
    price: float
    distance_miles: Optional[float] = None
    distance_text: Optional[str] = None
    duration_text: Optional[str] = None
    service_type: Optional[str] = "standard"
    is_scheduled: bool = True
    status: str = "pending"

# ==================== FUNCIONES DE BASE DE DATOS ====================

def get_user_by_username(username: str):
    """Obtener usuario por username"""
    if USE_SUPABASE:
        return SupabaseDB.get_user_by_username(username)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()
        return dict(user) if user else None

def get_user_by_id(user_id: int):
    """Obtener usuario por ID"""
    if USE_SUPABASE:
        return SupabaseDB.get_user_by_id(user_id)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        conn.close()
        return dict(user) if user else None

def create_user_db(username: str, email: str, password_hash: str, full_name: str, roles: list, allowed_apps: list):
    """Crear usuario en base de datos"""
    if USE_SUPABASE:
        return SupabaseDB.create_user(username, email, password_hash, full_name, roles, allowed_apps)
    else:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, email, password_hash, full_name, roles, allowed_apps)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, password_hash, full_name, json.dumps(roles), json.dumps(allowed_apps)))
            conn.commit()
            user_id = cur.lastrowid
            conn.close()
            return {"id": user_id, "username": username, "email": email, "full_name": full_name, 
                    "roles": roles, "allowed_apps": allowed_apps, "status": "active"}
        except sqlite3.IntegrityError:
            conn.close()
            raise HTTPException(status_code=400, detail="Username or email already exists")

def save_refresh_token(user_id: int, token: str, expires_at: str):
    """Guardar refresh token"""
    if USE_SUPABASE:
        return SupabaseDB.create_refresh_token(user_id, token, expires_at)
    else:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                    (user_id, token, expires_at))
        conn.commit()
        conn.close()

def get_refresh_token(token: str):
    """Obtener refresh token"""
    if USE_SUPABASE:
        return SupabaseDB.get_refresh_token(token)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0", (token,))
        token_row = cur.fetchone()
        conn.close()
        return dict(token_row) if token_row else None

def revoke_refresh_token(token: str):
    """Revocar refresh token"""
    if USE_SUPABASE:
        return SupabaseDB.revoke_refresh_token(token)
    else:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,))
        conn.commit()
        conn.close()

def create_booking_db(user_id: int, booking: BookingCreate):
    """Crear reserva"""
    if USE_SUPABASE:
        booking_data = {
            'pickup_address': booking.pickup_address,
            'pickup_lat': booking.pickup_lat,
            'pickup_lng': booking.pickup_lng,
            'destination_address': booking.destination_address,
            'destination_lat': booking.destination_lat,
            'destination_lng': booking.destination_lng,
            'pickup_time': booking.pickup_time,
            'vehicle_name': booking.vehicle_name,
            'passengers': booking.passengers,
            'price': booking.price,
            'distance_miles': booking.distance_miles,
            'distance_text': booking.distance_text,
            'duration_text': booking.duration_text,
            'service_type': booking.service_type,
            'is_scheduled': booking.is_scheduled,
            'status': booking.status
        }
        return SupabaseDB.create_booking(user_id, booking_data)
    else:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO vlx_bookings (
                user_id, pickup_address, pickup_lat, pickup_lng,
                destination_address, destination_lat, destination_lng,
                pickup_time, vehicle_name, passengers, price,
                distance_miles, distance_text, duration_text,
                service_type, is_scheduled, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, booking.pickup_address, booking.pickup_lat, booking.pickup_lng,
              booking.destination_address, booking.destination_lat, booking.destination_lng,
              booking.pickup_time, booking.vehicle_name, booking.passengers, booking.price,
              booking.distance_miles, booking.distance_text, booking.duration_text,
              booking.service_type, 1 if booking.is_scheduled else 0, booking.status))
        conn.commit()
        booking_id = cur.lastrowid
        cur.execute("SELECT * FROM vlx_bookings WHERE id = ?", (booking_id,))
        result = cur.fetchone()
        conn.close()
        return dict(result) if result else None

def get_user_bookings(user_id: int):
    """Obtener reservas de usuario"""
    if USE_SUPABASE:
        return SupabaseDB.get_user_bookings(user_id)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM vlx_bookings WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

def get_all_users():
    """Obtener todos los usuarios"""
    if USE_SUPABASE:
        return SupabaseDB.get_all_users()
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE status != 'deleted'")
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]

# ==================== JWT ====================
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: int) -> tuple:
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": str(user_id), "exp": expire, "type": "refresh"}
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, expire.isoformat()

def verify_token(token: str, token_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != token_type:
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = verify_token(credentials.credentials, "access")
    return payload

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Verificar que el usuario sea admin o manager"""
    roles = current_user.get("roles", [])
    if "admin" not in roles and "manager" not in roles:
        raise HTTPException(
            status_code=403, 
            detail="Acceso denegado: Se requiere rol de admin o manager"
        )
    return current_user

# ==================== ENDPOINTS ====================
@app.get("/")
def root():
    db_type = "Supabase (Cloud)" if USE_SUPABASE else "SQLite (Local)"
    return {
        "message": "VaneLux/Conexaship API",
        "version": "2.0.0",
        "database": db_type,
        "docs": "/docs"
    }

@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    user_row = get_user_by_username(req.username)
    
    if not user_row or not bcrypt.checkpw(req.password.encode(), user_row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user_id = user_row["id"]
    roles = user_row["roles"] if isinstance(user_row["roles"], list) else json.loads(user_row["roles"])
    allowed_apps = user_row["allowed_apps"] if isinstance(user_row["allowed_apps"], list) else json.loads(user_row["allowed_apps"])
    
    # Validar que el usuario tenga acceso a la app solicitada
    if req.app_name and req.app_name not in allowed_apps:
        raise HTTPException(
            status_code=403, 
            detail=f"No tienes acceso a {req.app_name.capitalize()}. Apps permitidas: {', '.join(allowed_apps)}"
        )
    
    access_token = create_access_token({
        "sub": str(user_id),
        "username": user_row["username"],
        "roles": roles,
        "allowed_apps": allowed_apps
    })
    refresh_token, expires_at = create_refresh_token(user_id)
    
    save_refresh_token(user_id, refresh_token, expires_at)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user_id,
            username=user_row["username"],
            email=user_row["email"],
            full_name=user_row["full_name"] or user_row["username"],
            roles=roles,
            allowed_apps=allowed_apps,
            status=user_row["status"]
        )
    )

@app.post("/api/v1/auth/login-card", response_model=TokenResponse)
def login_with_card(card_uid: str, app_name: Optional[str] = None):
    """Login usando tarjeta RFID"""
    # Buscar usuario por card_uid
    if USE_SUPABASE:
        response = SupabaseDB.supabase.table("users").select("*").eq("card_uid", card_uid).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Card not found")
        user_row = response.data[0]
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        user_row = conn.execute("SELECT * FROM users WHERE card_uid = ?", (card_uid,)).fetchone()
        conn.close()
        if not user_row:
            raise HTTPException(status_code=404, detail="Card not found")
        user_row = dict(user_row)
    
    user_id = user_row["id"]
    roles = user_row["roles"] if isinstance(user_row["roles"], list) else json.loads(user_row["roles"])
    allowed_apps = user_row["allowed_apps"] if isinstance(user_row["allowed_apps"], list) else json.loads(user_row["allowed_apps"])
    
    # Validar app_name si se proporciona
    if app_name and app_name not in allowed_apps:
        raise HTTPException(
            status_code=403,
            detail=f"No tienes acceso a {app_name.capitalize()}. Apps permitidas: {', '.join(allowed_apps)}"
        )
    
    access_token = create_access_token({
        "sub": str(user_id),
        "username": user_row["username"],
        "roles": roles,
        "allowed_apps": allowed_apps
    })
    refresh_token, expires_at = create_refresh_token(user_id)
    
    save_refresh_token(user_id, refresh_token, expires_at)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user_id,
            username=user_row["username"],
            email=user_row["email"],
            full_name=user_row["full_name"] or user_row["username"],
            roles=roles,
            allowed_apps=allowed_apps,
            status=user_row["status"]
        )
    )

@app.post("/api/v1/auth/register", response_model=UserResponse)
def register(user: UserCreate):
    password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    new_user = create_user_db(user.username, user.email, password_hash, user.full_name, user.roles, user.allowed_apps)
    
    return UserResponse(
        id=new_user["id"],
        username=new_user["username"],
        email=new_user["email"],
        full_name=new_user["full_name"],
        roles=new_user["roles"],
        allowed_apps=new_user["allowed_apps"],
        status=new_user["status"]
    )

@app.get("/api/v1/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    user_row = get_user_by_id(int(current_user["sub"]))
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")
    
    roles = user_row["roles"] if isinstance(user_row["roles"], list) else json.loads(user_row["roles"])
    allowed_apps = user_row["allowed_apps"] if isinstance(user_row["allowed_apps"], list) else json.loads(user_row["allowed_apps"])
    
    return UserResponse(
        id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        full_name=user_row["full_name"] or user_row["username"],
        roles=roles,
        allowed_apps=allowed_apps,
        status=user_row["status"]
    )

@app.get("/api/v1/users")
def list_users(email: Optional[str] = None):
    users = get_all_users()
    
    if email:
        users = [u for u in users if u["email"] == email]
    
    users_list = []
    for u in users:
        roles = u["roles"] if isinstance(u["roles"], list) else json.loads(u["roles"])
        allowed_apps = u["allowed_apps"] if isinstance(u["allowed_apps"], list) else json.loads(u["allowed_apps"])
        
        users_list.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "full_name": u["full_name"] or u["username"],
            "roles": roles,
            "allowed_apps": allowed_apps,
            "status": u["status"]
        })
    
    return {"users": users_list}

@app.post("/api/v1/users/create-employee", response_model=UserResponse)
def create_employee(user: UserCreate, current_user: dict = Depends(require_admin)):
    """
    Crear nuevo empleado (Solo Admin/Manager)
    - Genera UID automáticamente
    - Hashea password con bcrypt
    - Asigna 'vanelux' a allowed_apps por defecto
    """
    # Verificar que el email no exista
    existing_user = get_user_by_username(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="El email ya está registrado")
    
    # Asegurar que 'vanelux' esté en allowed_apps para empleados
    if "vanelux" not in user.allowed_apps:
        user.allowed_apps.append("vanelux")
    
    # Hashear password
    password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    
    # Crear usuario en DB
    new_user = create_user_db(
        user.email,  # username = email
        user.email,
        password_hash,
        user.full_name,
        user.roles,
        user.allowed_apps
    )
    
    return UserResponse(
        id=new_user["id"],
        username=new_user["username"],
        email=new_user["email"],
        full_name=new_user["full_name"],
        roles=new_user["roles"],
        allowed_apps=new_user["allowed_apps"],
        status=new_user["status"]
    )

@app.post("/api/v1/vlx/bookings")
def create_booking(booking: BookingCreate, current_user: dict = Depends(get_current_user)):
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    new_booking = create_booking_db(int(current_user["sub"]), booking)
    return {"booking": new_booking}

@app.get("/api/v1/vlx/bookings")
def list_bookings(current_user: dict = Depends(get_current_user)):
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    bookings = get_user_bookings(int(current_user["sub"]))
    return {"bookings": bookings}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)
