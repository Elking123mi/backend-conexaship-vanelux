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
import stripe
import requests
import uuid

# Cargar variables de entorno
load_dotenv()

# Detectar si usar Supabase o SQLite
USE_SUPABASE = os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_KEY")

if USE_SUPABASE:
    from supabase_config import init_supabase, SupabaseDB, get_supabase
    print("🟢 Usando SUPABASE (Base de datos en la nube)")
    init_supabase()
    supabase_client = get_supabase()
else:
    import sqlite3
    print("🟡 Usando SQLite local")
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logistics.db")
    supabase_client = None

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

# Configuración de Stripe
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY", "")
stripe.api_key = STRIPE_SECRET_KEY

# Configuración de Email (Mailgun)
MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")
MAILGUN_FROM_EMAIL = os.getenv("MAILGUN_FROM_EMAIL", "noreply@vanelux.com")

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
    # Campos de información del cliente (guest)
    guest_email: Optional[str] = None
    guest_first_name: Optional[str] = None
    guest_last_name: Optional[str] = None
    guest_phone: Optional[str] = None

class DriverApplication(BaseModel):
    """Modelo para aplicaciones de conductores"""
    full_name: str
    email: EmailStr
    phone: str
    driver_license: str
    license_expiry_date: str  # Formato: YYYY-MM-DD
    vehicle_type: str
    vehicle_make: str
    vehicle_model: str
    vehicle_year: int
    vehicle_color: str
    license_plate: str
    insurance_company: str
    insurance_policy_number: str
    insurance_expiry_date: str  # Formato: YYYY-MM-DD
    years_of_experience: int
    languages: Optional[str] = None
    has_background_check: bool = False
    additional_notes: Optional[str] = ""
    
    class Config:
        json_schema_extra = {
            "example": {
                "full_name": "Juan Pérez",
                "email": "juan.perez@example.com",
                "phone": "+1 305-555-0123",
                "driver_license": "D1234567",
                "license_expiry_date": "2026-12-31",
                "vehicle_type": "Sedan",
                "vehicle_make": "Mercedes-Benz",
                "vehicle_model": "S-Class",
                "vehicle_year": 2023,
                "vehicle_color": "Black",
                "license_plate": "ABC-1234",
                "insurance_company": "State Farm",
                "insurance_policy_number": "POL-123456789",
                "insurance_expiry_date": "2026-06-30",
                "years_of_experience": 8,
                "languages": "Español, Inglés",
                "has_background_check": True,
                "additional_notes": "Experiencia con clientes VIP"
            }
        }

class BookingAssignment(BaseModel):
    """Modelo para asignar un booking a un driver"""
    driver_id: int
    notes: Optional[str] = None

class BookingStatusUpdate(BaseModel):
    """Modelo para actualizar el estado de un booking"""
    status: str  # pending, assigned, in_progress, completed, cancelled
    notes: Optional[str] = None

class ApplicationAction(BaseModel):
    """Modelo para aprobar/rechazar aplicación de conductor"""
    admin_note: Optional[str] = None

class GoogleAuthRequest(BaseModel):
    """Modelo para autenticación con Google"""
    id_token: Optional[str] = None
    access_token: Optional[str] = None
    email: str
    name: Optional[str] = None
    photo_url: Optional[str] = None

class FacebookAuthRequest(BaseModel):
    """Modelo para autenticación con Facebook"""
    access_token: str
    email: str
    name: Optional[str] = None
    photo_url: Optional[str] = None

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

def get_user_by_email(email: str):
    """Obtener usuario por email"""
    if USE_SUPABASE:
        return SupabaseDB.get_user_by_email(email)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
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
    
    # Parsear roles (puede ser string simple, JSON array, o ya una lista)
    roles_raw = user_row.get("roles", "client")
    if isinstance(roles_raw, list):
        roles = roles_raw
    elif roles_raw and roles_raw.startswith("["):
        try:
            roles = json.loads(roles_raw)
        except:
            roles = [roles_raw]
    else:
        roles = [roles_raw] if roles_raw else ["client"]
    
    # Parsear allowed_apps (puede ser CSV, JSON array, o ya una lista)
    apps_raw = user_row.get("allowed_apps", "")
    if isinstance(apps_raw, list):
        allowed_apps = apps_raw
    elif apps_raw and apps_raw.startswith("["):
        try:
            allowed_apps = json.loads(apps_raw)
        except:
            allowed_apps = [a.strip() for a in apps_raw.split(",") if a.strip()]
    else:
        allowed_apps = [a.strip() for a in apps_raw.split(",") if a.strip()] if apps_raw else []
    
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

@app.post("/api/v1/auth/google", response_model=TokenResponse)
def google_auth(auth_data: GoogleAuthRequest):
    """
    Autenticación con Google OAuth
    - Verifica el ID token con Google
    - Crea usuario si no existe
    - Retorna access_token y refresh_token
    """
    try:
        # Verificar token con Google - soporta id_token y access_token
        if auth_data.id_token:
            # Verificar usando ID token (flujo nativo/móvil)
            google_verify_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={auth_data.id_token}"
            verify_response = requests.get(google_verify_url)
            if verify_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid Google ID token")
            token_info = verify_response.json()
            if token_info.get("email") != auth_data.email:
                raise HTTPException(status_code=401, detail="Email mismatch")
        elif auth_data.access_token:
            # Verificar usando access token (flujo web con GIS)
            userinfo_url = f"https://www.googleapis.com/oauth2/v3/userinfo?access_token={auth_data.access_token}"
            verify_response = requests.get(userinfo_url)
            if verify_response.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid Google access token")
            token_info = verify_response.json()
            if token_info.get("email") != auth_data.email:
                raise HTTPException(status_code=401, detail="Email mismatch")
        else:
            raise HTTPException(status_code=400, detail="id_token or access_token required")
        
        # Verificar si el usuario ya existe
        user = get_user_by_email(auth_data.email)
        
        if not user:
            # Crear nuevo usuario con OAuth
            username = auth_data.email.split('@')[0]
            password_hash = bcrypt.hashpw(str(uuid.uuid4()).encode(), bcrypt.gensalt()).decode()  # Random password
            
            user = create_user_db(
                username=username,
                email=auth_data.email,
                password_hash=password_hash,
                full_name=auth_data.name or username,
                roles=["passenger"],
                allowed_apps=["vanelux"]
            )
        
        # Generar tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=access_token_expires
        )
        
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=refresh_token_expires
        )
        
        # Preparar roles y allowed_apps
        roles = user["roles"] if isinstance(user["roles"], list) else json.loads(user["roles"])
        allowed_apps = user["allowed_apps"] if isinstance(user["allowed_apps"], list) else json.loads(user["allowed_apps"])
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                full_name=user["full_name"] or user["username"],
                roles=roles,
                allowed_apps=allowed_apps,
                status=user["status"]
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Google auth error: {e}")
        raise HTTPException(status_code=500, detail=f"Google authentication failed: {str(e)}")

@app.post("/api/v1/auth/facebook", response_model=TokenResponse)
def facebook_auth(auth_data: FacebookAuthRequest):
    """
    Autenticación con Facebook OAuth
    - Verifica el access token con Facebook
    - Crea usuario si no existe
    - Retorna access_token y refresh_token
    """
    try:
        # Verificar el access token con Facebook
        fb_verify_url = f"https://graph.facebook.com/me?fields=id,name,email&access_token={auth_data.access_token}"
        verify_response = requests.get(fb_verify_url)
        
        if verify_response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Facebook access token")
        
        fb_data = verify_response.json()
        
        # Validar que el email coincida
        if fb_data.get("email") != auth_data.email:
            raise HTTPException(status_code=401, detail="Email mismatch")
        
        # Verificar si el usuario ya existe
        user = get_user_by_email(auth_data.email)
        
        if not user:
            # Crear nuevo usuario con OAuth
            username = auth_data.email.split('@')[0]
            password_hash = bcrypt.hashpw(str(uuid.uuid4()).encode(), bcrypt.gensalt()).decode()  # Random password
            
            user = create_user_db(
                username=username,
                email=auth_data.email,
                password_hash=password_hash,
                full_name=auth_data.name or username,
                roles=["passenger"],
                allowed_apps=["vanelux"]
            )
        
        # Generar tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=access_token_expires
        )
        
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = create_refresh_token(
            data={"sub": str(user["id"]), "username": user["username"]},
            expires_delta=refresh_token_expires
        )
        
        # Preparar roles y allowed_apps
        roles = user["roles"] if isinstance(user["roles"], list) else json.loads(user["roles"])
        allowed_apps = user["allowed_apps"] if isinstance(user["allowed_apps"], list) else json.loads(user["allowed_apps"])
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse(
                id=user["id"],
                username=user["username"],
                email=user["email"],
                full_name=user["full_name"] or user["username"],
                roles=roles,
                allowed_apps=allowed_apps,
                status=user["status"]
            )
        )
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Facebook auth error: {e}")
        raise HTTPException(status_code=500, detail=f"Facebook authentication failed: {str(e)}")

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

@app.post("/api/v1/vlx/bookings/guest", status_code=status.HTTP_201_CREATED)
def create_guest_booking(booking: BookingCreate):
    """Crear booking sin autenticación (para guests)"""
    try:
        if USE_SUPABASE:
            booking_dict = booking.dict()
            booking_dict["user_id"] = None  # Guest booking
            booking_dict["status"] = "pending"
            booking_dict["created_at"] = datetime.utcnow().isoformat()
            
            result = supabase_client.table("vlx_bookings").insert(booking_dict).execute()
            
            if result.data and len(result.data) > 0:
                return result.data[0]
            else:
                raise HTTPException(status_code=500, detail="Error creating booking")
        else:
            # SQLite local
            new_booking = create_booking_db(None, booking)
            return new_booking
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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

@app.post("/api/v1/vlx/bookings/{booking_id}/send-confirmation", status_code=status.HTTP_200_OK)
def send_booking_confirmation(booking_id: int):
    """Enviar email de confirmación de reserva (sin autenticación)"""
    try:
        print(f"📧 Sending confirmation email for booking #{booking_id}")
        
        # Obtener booking de la base de datos
        if USE_SUPABASE:
            response = supabase_client.table("vlx_bookings").select("*").eq("id", booking_id).execute()
            if not response.data:
                raise HTTPException(status_code=404, detail="Booking not found")
            booking = response.data[0]
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM vlx_bookings WHERE id = ?", (booking_id,))
            booking_row = cur.fetchone()
            conn.close()
            if not booking_row:
                raise HTTPException(status_code=404, detail="Booking not found")
            booking = dict(booking_row)
        
        # Obtener email (de guest_email o de usuario)
        email = booking.get("guest_email")
        customer_name = booking.get("guest_first_name", "Customer")
        if booking.get("guest_last_name"):
            customer_name = f"{customer_name} {booking.get('guest_last_name')}"
        
        if not email and booking.get("user_id"):
            # Buscar email del usuario
            if USE_SUPABASE:
                user_response = supabase_client.table("users").select("email,full_name").eq("id", booking["user_id"]).execute()
                if user_response.data:
                    email = user_response.data[0].get("email")
                    customer_name = user_response.data[0].get("full_name") or customer_name
            else:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT email,full_name FROM users WHERE id = ?", (booking["user_id"],))
                user_row = cur.fetchone()
                conn.close()
                if user_row:
                    email = user_row["email"]
                    customer_name = user_row["full_name"] or customer_name
        
        if not email:
            print(f"❌ No email found for booking #{booking_id}")
            raise HTTPException(status_code=400, detail=f"No email found for booking #{booking_id}")
        
        print(f"📧 Sending to: {email}")
        
        # Preparar datos del email (usar campos reales de la BD)
        pickup = booking.get("pickup_address", "N/A")
        destination = booking.get("destination_address", "N/A")
        pickup_time = booking.get("pickup_time", "N/A")
        price = booking.get("price", 0)
        vehicle = booking.get("vehicle_name", "Standard Vehicle")
        passengers = booking.get("passengers", 1)
        
        # HTML del email
        email_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background-color: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .booking-details {{ background-color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .detail-row {{ padding: 10px 0; border-bottom: 1px solid #eee; }}
                .detail-label {{ font-weight: bold; color: #4F46E5; }}
                .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
                .button {{ display: inline-block; padding: 12px 30px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚗 VaneLux Transportation</h1>
                    <p>Booking Confirmation</p>
                </div>
                <div class="content">
                    <h2>Hello {customer_name}!</h2>
                    <p>Thank you for booking with VaneLux. Your ride has been confirmed!</p>
                    
                    <div class="booking-details">
                        <h3>📋 Booking Details #<span>{booking_id}</span></h3>
                        <div class="detail-row">
                            <span class="detail-label">📍 Pickup:</span> {pickup}
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">🎯 Destination:</span> {destination}
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">🕐 Pickup Time:</span> {pickup_time}
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">🚙 Vehicle:</span> {vehicle}
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">👥 Passengers:</span> {passengers}
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">💰 Total:</span> ${price:.2f} USD
                        </div>
                    </div>
                    
                    <p><strong>What's next?</strong></p>
                    <ul>
                        <li>Your driver will contact you 15 minutes before pickup</li>
                        <li>Please be ready at the pickup location at the scheduled time</li>
                        <li>Have a safe and comfortable journey!</li>
                    </ul>
                    
                    <center>
                        <a href="https://vane-lux.com" class="button">Visit Our Website</a>
                    </center>
                </div>
                <div class="footer">
                    <p>VaneLux Transportation Services</p>
                    <p>Questions? Contact us at support@vanelux.com</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Verificar si Mailgun está configurado
        if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
            print("⚠️ Mailgun not configured")
            return {
                "success": False,
                "message": f"Email service not configured (would send to {email})",
                "booking_id": booking_id,
                "warning": "MAILGUN_API_KEY or MAILGUN_DOMAIN not set"
            }
        
        # Enviar email via Mailgun
        from_email = MAILGUN_FROM_EMAIL if MAILGUN_FROM_EMAIL else f"VaneLux <mailgun@{MAILGUN_DOMAIN}>"
        
        response = requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": from_email,
                "to": email,
                "subject": f"🚗 VaneLux Booking Confirmation #{booking_id}",
                "html": email_html
            }
        )
        
        if response.status_code == 200:
            print(f"✅ Email sent successfully to {email}")
            return {
                "success": True,
                "message": f"Confirmation email sent to {email}",
                "booking_id": booking_id
            }
        else:
            print(f"❌ Failed to send email: {response.text}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to send email: {response.text}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== GESTIÓN DE BOOKINGS (ADMINISTRACIÓN) ====================

@app.get("/api/v1/vlx/bookings/pending")
def get_pending_bookings(current_user: dict = Depends(get_current_user)):
    """Obtener todos los bookings pendientes (sin asignar a driver)"""
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    try:
        if USE_SUPABASE:
            # Obtener bookings con status='pending' o driver_id=NULL
            response = supabase_client.table("vlx_bookings").select("*").or_("status.eq.pending,driver_id.is.null").order("created_at", desc=True).execute()
            bookings = response.data if response.data else []
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM vlx_bookings 
                WHERE status = 'pending' OR driver_id IS NULL 
                ORDER BY created_at DESC
            """)
            bookings = [dict(row) for row in cur.fetchall()]
            conn.close()
        
        return {"bookings": bookings, "count": len(bookings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/bookings/{booking_id}/assign")
def assign_booking_to_driver(
    booking_id: int, 
    assignment: BookingAssignment,
    current_user: dict = Depends(get_current_user)
):
    """Asignar un booking a un driver"""
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    try:
        # Verificar que el booking existe
        if USE_SUPABASE:
            booking_response = supabase_client.table("vlx_bookings").select("*").eq("id", booking_id).execute()
            if not booking_response.data:
                raise HTTPException(status_code=404, detail="Booking not found")
            
            # Verificar que el driver existe
            driver_response = supabase_client.table("users").select("id,full_name,email,roles").eq("id", assignment.driver_id).execute()
            if not driver_response.data:
                raise HTTPException(status_code=404, detail="Driver not found")
            
            driver = driver_response.data[0]
            # Verificar que el usuario tiene rol de driver
            roles = driver.get('roles', [])
            if isinstance(roles, str):
                import json
                roles = json.loads(roles) if roles else []
            if 'driver' not in roles:
                raise HTTPException(status_code=400, detail="User is not a driver")
            
            # Asignar el booking
            update_data = {
                "driver_id": assignment.driver_id,
                "status": "assigned",
                "assigned_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            if assignment.notes:
                update_data["admin_notes"] = assignment.notes
            
            result = supabase_client.table("vlx_bookings").update(update_data).eq("id", booking_id).execute()
            
            if not result.data:
                raise HTTPException(status_code=500, detail="Failed to assign booking")
            
            return {
                "success": True,
                "message": f"Booking assigned to {driver['full_name']}",
                "booking_id": booking_id,
                "driver_id": assignment.driver_id,
                "driver_name": driver['full_name']
            }
        else:
            # SQLite local
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            
            # Verificar booking
            cur.execute("SELECT * FROM vlx_bookings WHERE id = ?", (booking_id,))
            if not cur.fetchone():
                conn.close()
                raise HTTPException(status_code=404, detail="Booking not found")
            
            # Verificar driver
            cur.execute("SELECT id, full_name FROM users WHERE id = ?", (assignment.driver_id,))
            driver = cur.fetchone()
            if not driver:
                conn.close()
                raise HTTPException(status_code=404, detail="Driver not found")
            
            # Asignar booking
            cur.execute("""
                UPDATE vlx_bookings 
                SET driver_id = ?, status = 'assigned', assigned_at = ?, updated_at = ?
                WHERE id = ?
            """, (assignment.driver_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), booking_id))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "message": f"Booking assigned to driver",
                "booking_id": booking_id,
                "driver_id": assignment.driver_id
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vlx/bookings/driver/{driver_id}")
def get_driver_bookings(driver_id: int, current_user: dict = Depends(get_current_user)):
    """Obtener todos los bookings asignados a un driver específico"""
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    # Verificar que el usuario es el driver o es admin
    user_id = int(current_user["sub"])
    roles = current_user.get("roles", [])
    
    if user_id != driver_id and "admin" not in roles and "manager" not in roles:
        raise HTTPException(status_code=403, detail="You can only view your own bookings")
    
    try:
        if USE_SUPABASE:
            response = supabase_client.table("vlx_bookings").select("*").eq("driver_id", driver_id).order("pickup_time", desc=False).execute()
            bookings = response.data if response.data else []
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM vlx_bookings 
                WHERE driver_id = ? 
                ORDER BY pickup_time ASC
            """, (driver_id,))
            bookings = [dict(row) for row in cur.fetchall()]
            conn.close()
        
        return {"bookings": bookings, "count": len(bookings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/v1/vlx/bookings/{booking_id}/status")
def update_booking_status(
    booking_id: int,
    status_update: BookingStatusUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Actualizar el estado de un booking (driver o admin)"""
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    allowed_statuses = ['pending', 'assigned', 'in_progress', 'completed', 'cancelled']
    if status_update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {', '.join(allowed_statuses)}"
        )
    
    try:
        if USE_SUPABASE:
            # Verificar que el booking existe
            booking_response = supabase_client.table("vlx_bookings").select("*").eq("id", booking_id).execute()
            if not booking_response.data:
                raise HTTPException(status_code=404, detail="Booking not found")
            
            booking = booking_response.data[0]
            user_id = int(current_user["sub"])
            roles = current_user.get("roles", [])
            
            # Verificar permisos: solo el driver asignado o un admin puede actualizar
            if booking.get('driver_id') != user_id and 'admin' not in roles and 'manager' not in roles:
                raise HTTPException(status_code=403, detail="You can only update your own bookings")
            
            # Actualizar estado
            update_data = {
                "status": status_update.status,
                "updated_at": datetime.utcnow().isoformat()
            }
            
            # Agregar timestamps según el estado
            if status_update.status == 'in_progress':
                update_data["started_at"] = datetime.utcnow().isoformat()
            elif status_update.status == 'completed':
                update_data["completed_at"] = datetime.utcnow().isoformat()
            
            if status_update.notes:
                update_data["driver_notes"] = status_update.notes
            
            result = supabase_client.table("vlx_bookings").update(update_data).eq("id", booking_id).execute()
            
            if not result.data:
                raise HTTPException(status_code=500, detail="Failed to update booking status")
            
            return {
                "success": True,
                "message": f"Booking status updated to {status_update.status}",
                "booking_id": booking_id,
                "status": status_update.status
            }
        else:
            # SQLite local
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            
            cur.execute("""
                UPDATE vlx_bookings 
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (status_update.status, datetime.utcnow().isoformat(), booking_id))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "message": f"Booking status updated to {status_update.status}",
                "booking_id": booking_id,
                "status": status_update.status
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== PRODUCTOS / INVENTARIO ====================

class ProductCreate(BaseModel):
    sku: str
    name: str
    description: Optional[str] = None
    price: float
    stock: int = 0
    category: Optional[str] = "General"
    expiry_date: Optional[str] = None
    image_url: Optional[str] = None
    barcode: Optional[str] = None
    min_stock: Optional[int] = 0
    supplier: Optional[str] = None
    cost_price: Optional[float] = None

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    stock: Optional[int] = None
    category: Optional[str] = None
    expiry_date: Optional[str] = None
    image_url: Optional[str] = None
    barcode: Optional[str] = None
    min_stock: Optional[int] = None
    supplier: Optional[str] = None
    cost_price: Optional[float] = None
    status: Optional[str] = None

# ============= MODELOS DE STRIPE =============
class StripePaymentIntent(BaseModel):
    amount: float
    currency: str = "usd"
    description: Optional[str] = None

class CheckoutSessionRequest(BaseModel):
    booking_id: int
    amount: float
    currency: str = "usd"
    customer_email: Optional[str] = None
    success_url: str
    cancel_url: str

class StripePaymentConfirm(BaseModel):
    payment_intent_id: str
    user_id: int
    trip_id: Optional[int] = None
    booking_id: Optional[int] = None
    amount: float
    description: Optional[str] = None

@app.get("/api/v1/products")
def list_products(
    category: Optional[str] = None,
    status: Optional[str] = "active",
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Listar productos (acceso público para Conexaship Public)"""
    try:
        if USE_SUPABASE:
            query = supabase_client.table('products').select('*')
            
            if category:
                query = query.eq('category', category)
            if status:
                query = query.eq('status', status)
            if search:
                query = query.or_(f"name.ilike.%{search}%,sku.ilike.%{search}%,description.ilike.%{search}%")
            
            query = query.range(offset, offset + limit - 1).order('name')
            response = query.execute()
            
            return {"products": response.data or [], "count": len(response.data or [])}
        else:
            # SQLite
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            
            query = "SELECT * FROM products WHERE 1=1"
            params = []
            
            if category:
                query += " AND category = ?"
                params.append(category)
            if status:
                query += " AND status = ?"
                params.append(status)
            if search:
                query += " AND (name LIKE ? OR sku LIKE ? OR description LIKE ?)"
                search_term = f"%{search}%"
                params.extend([search_term, search_term, search_term])
            
            query += f" ORDER BY name LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cur.execute(query, params)
            products = [dict(row) for row in cur.fetchall()]
            conn.close()
            
            return {"products": products, "count": len(products)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/products/{sku}")
def get_product(sku: str):
    """Obtener producto por SKU (acceso público)"""
    try:
        if USE_SUPABASE:
            response = supabase_client.table('products').select('*').eq('sku', sku).execute()
            if not response.data:
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            return {"product": response.data[0]}
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM products WHERE sku = ?", (sku,))
            product = cur.fetchone()
            conn.close()
            
            if not product:
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            return {"product": dict(product)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/products", status_code=status.HTTP_201_CREATED)
def create_product(product: ProductCreate, current_user: dict = Depends(get_current_user)):
    """Crear nuevo producto (requiere autenticación)"""
    # Verificar roles
    user_roles = current_user.get("roles", [])
    if not any(role in ["ceo", "executive", "admin", "manager"] for role in user_roles):
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    
    try:
        if USE_SUPABASE:
            # Verificar si el SKU ya existe
            check = supabase_client.table('products').select('id').eq('sku', product.sku).execute()
            if check.data:
                raise HTTPException(status_code=400, detail="SKU ya existe")
            
            # Crear producto
            new_product = {
                "sku": product.sku,
                "name": product.name,
                "description": product.description,
                "price": product.price,
                "stock": product.stock,
                "category": product.category,
                "expiry_date": product.expiry_date,
                "image_url": product.image_url,
                "barcode": product.barcode,
                "min_stock": product.min_stock,
                "supplier": product.supplier,
                "cost_price": product.cost_price,
                "status": "active"
            }
            
            response = supabase_client.table('products').insert(new_product).execute()
            return {"product": response.data[0], "message": "Producto creado exitosamente"}
        else:
            # SQLite
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            
            # Verificar SKU
            cur.execute("SELECT id FROM products WHERE sku = ?", (product.sku,))
            if cur.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="SKU ya existe")
            
            cur.execute("""
                INSERT INTO products (sku, name, description, price, stock, category, expiry_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (product.sku, product.name, product.description, product.price, 
                  product.stock, product.category, product.expiry_date))
            
            conn.commit()
            product_id = cur.lastrowid
            
            cur.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            conn.row_factory = sqlite3.Row
            new_product = dict(cur.fetchone())
            conn.close()
            
            return {"product": new_product, "message": "Producto creado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/v1/products/{sku}")
def update_product(sku: str, product: ProductUpdate, current_user: dict = Depends(get_current_user)):
    """Actualizar producto (requiere autenticación)"""
    user_roles = current_user.get("roles", [])
    if not any(role in ["ceo", "executive", "admin", "manager"] for role in user_roles):
        raise HTTPException(status_code=403, detail="Permisos insuficientes")
    
    try:
        # Construir diccionario solo con campos no-None
        update_data = {k: v for k, v in product.dict().items() if v is not None}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No hay datos para actualizar")
        
        if USE_SUPABASE:
            response = supabase_client.table('products').update(update_data).eq('sku', sku).execute()
            if not response.data:
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            return {"product": response.data[0], "message": "Producto actualizado exitosamente"}
        else:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            
            # Construir query dinámica
            set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
            values = list(update_data.values()) + [sku]
            
            cur.execute(f"UPDATE products SET {set_clause} WHERE sku = ?", values)
            
            if cur.rowcount == 0:
                conn.close()
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            
            conn.commit()
            
            cur.execute("SELECT * FROM products WHERE sku = ?", (sku,))
            conn.row_factory = sqlite3.Row
            updated_product = dict(cur.fetchone())
            conn.close()
            
            return {"product": updated_product, "message": "Producto actualizado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/products/{sku}")
def delete_product(sku: str, current_user: dict = Depends(get_current_user)):
    """Eliminar producto (requiere autenticación CEO/Admin)"""
    user_roles = current_user.get("roles", [])
    if not any(role in ["ceo", "admin"] for role in user_roles):
        raise HTTPException(status_code=403, detail="Solo CEO/Admin pueden eliminar productos")
    
    try:
        if USE_SUPABASE:
            response = supabase_client.table('products').delete().eq('sku', sku).execute()
            if not response.data:
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            return {"message": f"Producto {sku} eliminado exitosamente"}
        else:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("DELETE FROM products WHERE sku = ?", (sku,))
            
            if cur.rowcount == 0:
                conn.close()
                raise HTTPException(status_code=404, detail="Producto no encontrado")
            
            conn.commit()
            conn.close()
            return {"message": f"Producto {sku} eliminado exitosamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/products/categories/list")
def list_categories():
    """Listar todas las categorías de productos"""
    try:
        if USE_SUPABASE:
            response = supabase_client.table('product_categories').select('*').order('name').execute()
            return {"categories": response.data or []}
        else:
            # Categorías por defecto en SQLite
            default_categories = [
                {"id": 1, "name": "Electrónica", "description": "Dispositivos electrónicos y accesorios"},
                {"id": 2, "name": "Oficina", "description": "Artículos de oficina y papelería"},
                {"id": 3, "name": "Computación", "description": "Computadoras y accesorios"},
                {"id": 4, "name": "Hogar", "description": "Artículos para el hogar"},
                {"id": 5, "name": "General", "description": "Productos generales"}
            ]
            return {"categories": default_categories}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============= ENDPOINTS DE STRIPE =============

@app.get("/api/v1/vlx/payments/stripe/config")
def get_stripe_config():
    """Obtener la clave pública de Stripe para el cliente"""
    if not STRIPE_PUBLIC_KEY:
        raise HTTPException(
            status_code=500,
            detail="Stripe no está configurado. Agregue STRIPE_PUBLIC_KEY en variables de entorno."
        )
    
    return {
        "publishable_key": STRIPE_PUBLIC_KEY,
        "currency": "usd"
    }

@app.post("/api/v1/vlx/payments/stripe/create-intent", status_code=status.HTTP_200_OK)
def create_payment_intent(payment_data: StripePaymentIntent):
    """Crear un Payment Intent de Stripe - No requiere autenticación previa"""
    try:
        # Validar monto
        if payment_data.amount <= 0:
            raise HTTPException(status_code=400, detail="El monto debe ser mayor a 0")
        
        # Convertir a centavos (Stripe usa centavos)
        amount_cents = int(payment_data.amount * 100)
        
        # Crear Payment Intent en Stripe
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=payment_data.currency,
            description=payment_data.description or "Pago VaneLux",
            automatic_payment_methods={"enabled": True}
        )
        
        return {
            "client_secret": intent.client_secret,
            "payment_intent_id": intent.id,
            "amount": payment_data.amount,
            "currency": payment_data.currency
        }
        
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Error de Stripe: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vlx/payments/stripe/create-checkout-session", status_code=status.HTTP_200_OK)
def create_checkout_session(checkout_request: CheckoutSessionRequest):
    """Crear una Checkout Session de Stripe para redirigir al usuario"""
    try:
        # Validar monto
        if checkout_request.amount <= 0:
            raise HTTPException(status_code=400, detail="El monto debe ser mayor a 0")
        
        # Convertir a centavos (Stripe usa centavos)
        amount_cents = int(checkout_request.amount * 100)
        
        # Crear Checkout Session en Stripe
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': checkout_request.currency,
                    'product_data': {
                        'name': 'VaneLux Transportation Service',
                        'description': f'Booking #{checkout_request.booking_id}',
                    },
                    'unit_amount': amount_cents,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=checkout_request.success_url,
            cancel_url=checkout_request.cancel_url,
            customer_email=checkout_request.customer_email,
            metadata={
                'booking_id': str(checkout_request.booking_id)
            }
        )
        
        return {
            "session_id": session.id,
            "url": session.url
        }
        
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Error de Stripe: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vlx/payments/stripe/confirm", status_code=status.HTTP_201_CREATED)
def confirm_payment(
    payment_data: StripePaymentConfirm,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Confirmar un pago de Stripe y guardarlo en la base de datos"""
    try:
        # Verificar token
        token_data = verify_token(credentials.credentials)
        
        # Verificar el Payment Intent con Stripe
        intent = stripe.PaymentIntent.retrieve(payment_data.payment_intent_id)
        
        if intent.status != "succeeded":
            raise HTTPException(
                status_code=400,
                detail=f"El pago no se completó. Estado: {intent.status}"
            )
        
        # Guardar en base de datos
        if USE_SUPABASE:
            # Guardar en Supabase
            payment_record = {
                "user_id": payment_data.user_id,
                "trip_id": payment_data.trip_id,
                "booking_id": payment_data.booking_id,
                "amount": payment_data.amount,
                "payment_method": "stripe",
                "status": "completed",
                "stripe_payment_intent_id": payment_data.payment_intent_id,
                "description": payment_data.description or "Pago con Stripe",
                "created_at": datetime.utcnow().isoformat()
            }
            
            result = supabase_client.table("payments").insert(payment_record).execute()
            
            if not result.data:
                raise HTTPException(status_code=500, detail="Error al guardar el pago")
            
            payment_id = result.data[0]["id"]
        else:
            # Guardar en SQLite local
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO payments 
                (user_id, trip_id, booking_id, amount, payment_method, status, stripe_payment_intent_id, description, created_at)
                VALUES (?, ?, ?, ?, 'stripe', 'completed', ?, ?, ?)
            """, (
                payment_data.user_id,
                payment_data.trip_id,
                payment_data.booking_id,
                payment_data.amount,
                payment_data.payment_intent_id,
                payment_data.description or "Pago con Stripe",
                datetime.utcnow().isoformat()
            ))
            
            payment_id = cursor.lastrowid
            conn.commit()
            conn.close()
        
        return {
            "message": "Pago confirmado exitosamente",
            "payment_id": payment_id,
            "stripe_payment_intent_id": payment_data.payment_intent_id,
            "amount": payment_data.amount,
            "status": "completed"
        }
        
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Error de Stripe: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CONDUCTORES / DRIVERS ====================

def send_driver_application_email(application_data: dict, application_id: str, approval_token: str):
    """
    Envía email al admin con los datos de la aplicación del conductor usando Mailgun API.
    Incluye botones para aprobar/rechazar.
    """
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@vanelux.com')
    backend_url = os.getenv('BACKEND_URL', 'https://web-production-700fe.up.railway.app')
    
    # Formatear boolean a texto
    background_check_text = "✅ Sí" if application_data.get('has_background_check') else "❌ No"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background-color: #0B3254; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 20px; }}
            .section {{ margin-bottom: 30px; }}
            .section h3 {{ color: #0B3254; border-bottom: 2px solid #D4AF37; padding-bottom: 10px; }}
            .info-row {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
            .label {{ font-weight: bold; display: inline-block; width: 200px; }}
            .value {{ display: inline-block; }}
            .footer {{ background-color: #f4f4f4; padding: 15px; text-align: center; margin-top: 30px; }}
            .alert {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
            .button-container {{ text-align: center; margin: 30px 0; }}
            .btn {{ display: inline-block; padding: 15px 40px; margin: 10px; text-decoration: none; color: white; border-radius: 5px; font-weight: bold; font-size: 16px; }}
            .btn-approve {{ background-color: #10b981; }}
            .btn-approve:hover {{ background-color: #059669; }}
            .btn-reject {{ background-color: #ef4444; }}
            .btn-reject:hover {{ background-color: #dc2626; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🚗 Nueva Aplicación de Conductor</h1>
        </div>
        
        <div class="content">
            <div class="alert">
                <strong>ID de Aplicación:</strong> {application_id}<br>
                <strong>Estado:</strong> Pendiente de Revisión
            </div>

            <div class="section">
                <h3>📋 Información Personal</h3>
                <div class="info-row">
                    <span class="label">Nombre Completo:</span>
                    <span class="value">{application_data['full_name']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Email:</span>
                    <span class="value">{application_data['email']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Teléfono:</span>
                    <span class="value">{application_data['phone']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Licencia de Conducir:</span>
                    <span class="value">{application_data['driver_license']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Licencia Expira:</span>
                    <span class="value">{application_data['license_expiry_date']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Años de Experiencia:</span>
                    <span class="value">{application_data['years_of_experience']} años</span>
                </div>
                <div class="info-row">
                    <span class="label">Idiomas:</span>
                    <span class="value">{application_data.get('languages', 'No especificado')}</span>
                </div>
                <div class="info-row">
                    <span class="label">Background Check:</span>
                    <span class="value">{background_check_text}</span>
                </div>
            </div>

            <div class="section">
                <h3>🚘 Información del Vehículo</h3>
                <div class="info-row">
                    <span class="label">Tipo de Vehículo:</span>
                    <span class="value">{application_data['vehicle_type']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Marca:</span>
                    <span class="value">{application_data['vehicle_make']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Modelo:</span>
                    <span class="value">{application_data['vehicle_model']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Año:</span>
                    <span class="value">{application_data['vehicle_year']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Color:</span>
                    <span class="value">{application_data['vehicle_color']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Placa:</span>
                    <span class="value">{application_data['license_plate']}</span>
                </div>
            </div>

            <div class="section">
                <h3>🛡️ Información del Seguro</h3>
                <div class="info-row">
                    <span class="label">Compañía de Seguro:</span>
                    <span class="value">{application_data['insurance_company']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Número de Póliza:</span>
                    <span class="value">{application_data['insurance_policy_number']}</span>
                </div>
                <div class="info-row">
                    <span class="label">Seguro Expira:</span>
                    <span class="value">{application_data['insurance_expiry_date']}</span>
                </div>
            </div>

            <div class="section">
                <h3>📝 Notas Adicionales</h3>
                <p>{application_data.get('additional_notes', 'Ninguna')}</p>
            </div>
            
            <div class="button-container">
                <a href="{backend_url}/api/v1/vlx/drivers/approve/{application_id}?token={approval_token}" class="btn btn-approve">
                    ✅ APROBAR CONDUCTOR
                </a>
                <a href="{backend_url}/api/v1/vlx/drivers/reject/{application_id}?token={approval_token}" class="btn btn-reject">
                    ❌ RECHAZAR SOLICITUD
                </a>
            </div>
        </div>

        <div class="footer">
            <p>Este email fue generado automáticamente por el sistema de VaneLux.</p>
        </div>
    </body>
    </html>
    """
    
    subject = f"Nueva Aplicación de Conductor - {application_data['full_name']}"
    
    # Enviar usando Mailgun API
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("⚠️ Mailgun not configured - email not sent")
        return False
    
    from_email = MAILGUN_FROM_EMAIL if MAILGUN_FROM_EMAIL else f"VaneLux <mailgun@{MAILGUN_DOMAIN}>"
    
    try:
        response = requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": from_email,
                "to": admin_email,
                "subject": subject,
                "html": html_body
            }
        )
        
        if response.status_code == 200:
            print(f"✅ Driver application email sent to {admin_email}")
            return True
        else:
            print(f"❌ Failed to send driver application email: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error sending driver application email: {str(e)}")
        return False


@app.post("/api/v1/vlx/drivers/apply", status_code=status.HTTP_201_CREATED)
def apply_as_driver(application: DriverApplication):
    """
    Endpoint para recibir aplicaciones de conductores.
    Guarda en Supabase y envía email al admin.
    """
    try:
        from datetime import datetime as dt
        
        # Validar fechas de expiración
        try:
            license_date = dt.strptime(application.license_expiry_date, "%Y-%m-%d").date()
            insurance_date = dt.strptime(application.insurance_expiry_date, "%Y-%m-%d").date()
            today = dt.today().date()
            
            if license_date <= today:
                raise HTTPException(
                    status_code=400,
                    detail="Driver license is expired or expires today"
                )
            
            if insurance_date <= today:
                raise HTTPException(
                    status_code=400,
                    detail="Insurance is expired or expires today"
                )
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid date format. Use YYYY-MM-DD: {str(e)}"
            )
        
        # Validar año del vehículo
        current_year = dt.today().year
        if application.vehicle_year < 2015 or application.vehicle_year > current_year + 1:
            raise HTTPException(
                status_code=400,
                detail=f"Vehicle year must be between 2015 and {current_year + 1}"
            )
        
        # Validar tipo de vehículo
        allowed_vehicle_types = ['Sedan', 'SUV', 'Van', 'Luxury', 'Other']
        if application.vehicle_type not in allowed_vehicle_types:
            raise HTTPException(
                status_code=400,
                detail=f"Vehicle type must be one of: {', '.join(allowed_vehicle_types)}"
            )
        
        # Validar experiencia
        if application.years_of_experience < 0:
            raise HTTPException(
                status_code=400,
                detail="Years of experience cannot be negative"
            )
        
        # Preparar datos para Supabase/SQLite
        application_data = {
            "full_name": application.full_name,
            "email": application.email,
            "phone": application.phone,
            "driver_license": application.driver_license,
            "license_expiry_date": application.license_expiry_date,
            "vehicle_type": application.vehicle_type,
            "vehicle_make": application.vehicle_make,
            "vehicle_model": application.vehicle_model,
            "vehicle_year": application.vehicle_year,
            "vehicle_color": application.vehicle_color,
            "license_plate": application.license_plate,
            "insurance_company": application.insurance_company,
            "insurance_policy_number": application.insurance_policy_number,
            "insurance_expiry_date": application.insurance_expiry_date,
            "years_of_experience": application.years_of_experience,
            "languages": application.languages,
            "has_background_check": application.has_background_check,
            "additional_notes": application.additional_notes,
            "status": "pending"
        }
        
        # Insertar en base de datos
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications').insert(application_data).execute()
            
            if not result.data:
                raise HTTPException(status_code=500, detail="Failed to save application")
            
            application_id = result.data[0]['id']
        else:
            # SQLite local
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO driver_applications 
                (full_name, email, phone, driver_license, license_expiry_date, 
                 vehicle_type, vehicle_make, vehicle_model, vehicle_year, vehicle_color, 
                 license_plate, insurance_company, insurance_policy_number, insurance_expiry_date,
                 years_of_experience, languages, has_background_check, additional_notes, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                application.full_name,
                application.email,
                application.phone,
                application.driver_license,
                application.license_expiry_date,
                application.vehicle_type,
                application.vehicle_make,
                application.vehicle_model,
                application.vehicle_year,
                application.vehicle_color,
                application.license_plate,
                application.insurance_company,
                application.insurance_policy_number,
                application.insurance_expiry_date,
                application.years_of_experience,
                application.languages,
                application.has_background_check,
                application.additional_notes,
                "pending",
                datetime.utcnow().isoformat()
            ))
            
            application_id = cursor.lastrowid
            conn.commit()
            conn.close()
        
        print(f"✅ Driver application saved: {application_id}")
        
        # Obtener approval_token de Supabase
        approval_token = None
        try:
            if USE_SUPABASE:
                result = supabase_client.table('driver_applications').select('approval_token').eq('id', application_id).single().execute()
                approval_token = str(result.data['approval_token'])
            else:
                approval_token = str(uuid.uuid4())
        except Exception as e:
            print(f"⚠️ Could not get approval_token: {e}")
            approval_token = str(uuid.uuid4())
        
        # Enviar email al admin
        email_sent = False
        try:
            email_sent = send_driver_application_email(
                application_data=application.dict(),
                application_id=str(application_id),
                approval_token=approval_token
            )
        except Exception as email_error:
            print(f"⚠️ Failed to send email: {email_error}")
            # No fallar el request si el email falla
        
        return {
            "success": True,
            "message": "Driver application submitted successfully",
            "application_id": str(application_id),
            "email_sent": email_sent
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in driver application: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


def send_driver_approval_email(driver_email: str, driver_name: str, setup_token: str, expires_at: str):
    """
    Envía email al conductor con link único de registro de una sola vez.
    """
    app_base_url = os.getenv('APP_BASE_URL', 'https://vane-lux.com')
    setup_link = f"{app_base_url}/#/set-password?token={setup_token}"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .header {{ background-color: #10b981; color: white; padding: 30px; text-align: center; }}
            .content {{ padding: 30px; max-width: 600px; margin: 0 auto; }}
            .button {{ display: inline-block; padding: 15px 40px; background-color: #3b82f6; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }}
            .footer {{ background-color: #f4f4f4; padding: 15px; text-align: center; margin-top: 30px; font-size: 12px; color: #666; }}
            .alert {{ background-color: #dcfce7; border-left: 4px solid: #10b981; padding: 15px; margin: 20px 0; }}
            .warning {{ background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🎉 ¡Felicidades {driver_name}!</h1>
        </div>
        
        <div class="content">
            <div class="alert">
                <strong>✅ Tu aplicación ha sido APROBADA</strong>
            </div>
            
            <p>Nos complace informarte que tu solicitud para ser conductor de VaneLux ha sido aprobada.</p>
            
            <h3>📝 Próximo Paso: Completar tu Registro</h3>
            <p>Para activar tu cuenta, necesitas completar tu registro haciendo click en el siguiente botón:</p>
            
            <div style="text-align: center;">
                <a href="{setup_link}" class="button" style="background-color: #D4AF37; color: #0B3254;">
                    ✅ Create My Password
                </a>
            </div>
            
            <p style="text-align: center; font-size: 12px; color: #666;">
                Or copy this link: <a href="{setup_link}">{setup_link}</a>
            </p>
            
            <div class="warning">
                <strong>⚠️ Importante:</strong>
                <ul>
                    <li>Este link es de <strong>una sola vez</strong> y expira el {expires_at}</li>
                    <li>Una vez que completes el registro, no podrás volver a usar este link</li>
                    <li>Asegúrate de crear una contraseña segura</li>
                </ul>
            </div>
            
            <h3>📱 ¿Qué sigue después del registro?</h3>
            <ol>
                <li>Descarga la app de VaneLux Driver en tu teléfono</li>
                <li>Inicia sesión con tu email y contraseña</li>
                <li>Completa tu perfil y documentos</li>
                <li>¡Empieza a recibir solicitudes de viaje!</li>
            </ol>
            
            <p><strong>¿Tienes preguntas?</strong> Responde a este email y te ayudaremos.</p>
        </div>

        <div class="footer">
            <p><strong>Vanelux</strong> | +1 (917) 599-5522 | info@vanelux.com</p>
            <p style="font-size: 11px; color: #999;">This email was generated automatically. If you didn't apply to be a driver, please ignore this message.</p>
        </div>
    </body>
    </html>
    """
    
    subject = "🎉 Your Vanelux Driver Application is Approved — Create Your Password"
    
    # Enviar usando Mailgun API
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("⚠️ Mailgun not configured - email not sent")
        return False
    
    from_email = MAILGUN_FROM_EMAIL if MAILGUN_FROM_EMAIL else f"VaneLux <mailgun@{MAILGUN_DOMAIN}>"
    
    try:
        response = requests.post(
            f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": from_email,
                "to": driver_email,
                "subject": subject,
                "html": html_body
            }
        )
        
        if response.status_code == 200:
            print(f"✅ Driver approval email sent to {driver_email}")
            return True
        else:
            print(f"❌ Failed to send approval email: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error sending approval email: {str(e)}")
        return False


@app.get("/api/v1/vlx/drivers/applications")
def get_driver_applications(status: Optional[str] = None):
    """
    Obtener lista de aplicaciones de conductores.
    Filtro opcional por status: pending, approved, rejected
    """
    try:
        if USE_SUPABASE:
            query = supabase_client.table('driver_applications').select('*')
            
            if status:
                query = query.eq('status', status)
            
            query = query.order('created_at', desc=True)
            result = query.execute()
            applications = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if status:
                cursor.execute(
                    """SELECT id, full_name, email, phone, driver_license, license_expiry_date,
                       vehicle_type, vehicle_make, vehicle_model, vehicle_year, vehicle_color,
                       license_plate, insurance_company, insurance_policy_number, insurance_expiry_date,
                       years_of_experience, languages, has_background_check, additional_notes,
                       status, created_at, approved_at, rejected_at, rejection_reason
                       FROM driver_applications WHERE status = ? ORDER BY created_at DESC""",
                    (status,)
                )
            else:
                cursor.execute(
                    """SELECT id, full_name, email, phone, driver_license, license_expiry_date,
                       vehicle_type, vehicle_make, vehicle_model, vehicle_year, vehicle_color,
                       license_plate, insurance_company, insurance_policy_number, insurance_expiry_date,
                       years_of_experience, languages, has_background_check, additional_notes,
                       status, created_at, approved_at, rejected_at, rejection_reason
                       FROM driver_applications ORDER BY created_at DESC"""
                )
            
            rows = cursor.fetchall()
            conn.close()
            
            applications = []
            for row in rows:
                applications.append({
                    'id': row[0],
                    'full_name': row[1],
                    'email': row[2],
                    'phone': row[3],
                    'driver_license': row[4],
                    'license_expiry_date': row[5],
                    'vehicle_type': row[6],
                    'vehicle_make': row[7],
                    'vehicle_model': row[8],
                    'vehicle_year': row[9],
                    'vehicle_color': row[10],
                    'license_plate': row[11],
                    'insurance_company': row[12],
                    'insurance_policy_number': row[13],
                    'insurance_expiry_date': row[14],
                    'years_of_experience': row[15],
                    'languages': row[16],
                    'has_background_check': bool(row[17]),
                    'additional_notes': row[18],
                    'status': row[19],
                    'created_at': row[20],
                    'approved_at': row[21],
                    'rejected_at': row[22],
                    'rejection_reason': row[23]
                })
        
        return {"applications": applications, "count": len(applications)}
        
    except Exception as e:
        print(f"❌ Error fetching driver applications: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/drivers/applications/{application_id}/approve")
def approve_application_by_admin(application_id: str, action: ApplicationAction):
    """
    Endpoint para que el admin apruebe una aplicación desde el panel de control.
    Genera un token de registro único y envía email al conductor.
    """
    try:
        # Obtener la aplicación
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE id = ?",
                (application_id,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = {
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'status': row[-7]
            }
        
        # Verificar que está pendiente
        if application['status'] != 'pending':
            raise HTTPException(
                status_code=400,
                detail=f"Cannot approve application with status: {application['status']}"
            )
        
        # Generar JWT token de setup (válido por 72 horas)
        expires_at = datetime.utcnow() + timedelta(hours=72)
        setup_token_data = {
            'type': 'driver_setup',
            'application_id': application_id,
            'email': application['email'],
            'full_name': application['full_name'],
            'exp': expires_at
        }
        setup_token = jwt.encode(setup_token_data, SECRET_KEY, algorithm=ALGORITHM)
        
        # Actualizar aplicación
        update_data = {
            'status': 'approved',
            'approved_at': datetime.utcnow().isoformat(),
            'setup_token': setup_token,
            'admin_note': action.admin_note
        }
        
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update(update_data)\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE driver_applications 
                   SET status = ?, approved_at = ?, setup_token = ?, admin_note = ?
                   WHERE id = ?""",
                ('approved', update_data['approved_at'], setup_token, action.admin_note, application_id)
            )
            conn.commit()
            conn.close()
        
        # Enviar email al conductor con link de setup
        email_sent = send_driver_approval_email(
            driver_email=application['email'],
            driver_name=application['full_name'],
            setup_token=setup_token,
            expires_at=expires_at.strftime('%Y-%m-%d %H:%M UTC')
        )
        
        app_base_url = os.getenv('APP_BASE_URL', 'https://vane-lux.com')
        setup_link = f"{app_base_url}/#/set-password?token={setup_token}"
        
        return {
            "success": True,
            "message": f"Application approved. Setup email sent to {application['email']}",
            "email_sent": email_sent,
            "email_error": None if email_sent else "Failed to send email",
            "setup_link": setup_link
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error approving application: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/drivers/applications/{application_id}/reject")
def reject_application_by_admin(application_id: str, action: ApplicationAction):
    """
    Endpoint para que el admin rechace una aplicación desde el panel de control.
    """
    try:
        # Obtener la aplicación
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE id = ?",
                (application_id,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = {
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'status': row[-7]
            }
        
        # Verificar que está pendiente
        if application['status'] != 'pending':
            raise HTTPException(
                status_code=400,
                detail=f"Cannot reject application with status: {application['status']}"
            )
        
        # Actualizar aplicación
        update_data = {
            'status': 'rejected',
            'rejected_at': datetime.utcnow().isoformat(),
            'rejection_reason': action.admin_note or 'No reason provided',
            'admin_note': action.admin_note
        }
        
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update(update_data)\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE driver_applications 
                   SET status = ?, rejected_at = ?, rejection_reason = ?, admin_note = ?
                   WHERE id = ?""",
                ('rejected', update_data['rejected_at'], update_data['rejection_reason'],
                 action.admin_note, application_id)
            )
            conn.commit()
            conn.close()
        
        return {
            "success": True,
            "message": f"Application rejected",
            "reason": update_data['rejection_reason']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error rejecting application: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/drivers/applications/{application_id}/resend-approval")
def resend_approval_email(application_id: str):
    """
    Reenviar email de aprobación a un driver (si no recibió el email o expiró el token).
    """
    try:
        # Obtener la aplicación
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE id = ?",
                (application_id,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = {
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'status': row[-7]
            }
        
        # Verificar que esté aprobada
        if application['status'] != 'approved':
            raise HTTPException(
                status_code=400,
                detail=f"Cannot resend email for application with status: {application['status']}"
            )
        
        # Generar nuevo JWT token de setup (válido por 72 horas)
        expires_at = datetime.utcnow() + timedelta(hours=72)
        setup_token_data = {
            'type': 'driver_setup',
            'application_id': application_id,
            'email': application['email'],
            'full_name': application['full_name'],
            'exp': expires_at
        }
        setup_token = jwt.encode(setup_token_data, SECRET_KEY, algorithm=ALGORITHM)
        
        # Actualizar setup_token en BD
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update({'setup_token': setup_token})\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE driver_applications SET setup_token = ? WHERE id = ?",
                (setup_token, application_id)
            )
            conn.commit()
            conn.close()
        
        # Reenviar email
        email_sent = send_driver_approval_email(
            driver_email=application['email'],
            driver_name=application['full_name'],
            setup_token=setup_token,
            expires_at=expires_at.strftime('%Y-%m-%d %H:%M UTC')
        )
        
        app_base_url = os.getenv('APP_BASE_URL', 'https://vane-lux.com')
        setup_link = f"{app_base_url}/#/set-password?token={setup_token}"
        
        return {
            "success": True,
            "email_sent": email_sent,
            "sent_to": application['email'],
            "setup_link": setup_link
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error resending approval email: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vlx/drivers/approve/{application_id}")
def approve_driver_application(application_id: str, token: str):
    """
    Endpoint para aprobar una aplicación de conductor desde el email del admin.
    Genera un token de registro único y envía email al conductor.
    """
    try:
        # Verificar que existe la aplicación y el token es válido
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .eq('approval_token', token)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found or invalid token")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE id = ? AND approval_token = ?",
                (application_id, token)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found or invalid token")
            
            # Convertir row a dict (asumiendo estructura de la tabla)
            application = {
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'status': row[-3]
            }
        
        # Verificar que está pendiente
        if application['status'] != 'pending':
            return {
                "success": False,
                "message": f"Esta aplicación ya fue {application['status']}",
                "status": application['status']
            }
        
        # Generar token de registro (válido por 24 horas)
        registration_token = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Actualizar aplicación
        update_data = {
            'status': 'approved',
            'approved_at': datetime.utcnow().isoformat(),
            'registration_token': registration_token,
            'token_expires_at': expires_at.isoformat()
        }
        
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update(update_data)\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE driver_applications 
                   SET status = ?, approved_at = ?, registration_token = ?, token_expires_at = ?
                   WHERE id = ?""",
                ('approved', datetime.utcnow().isoformat(), registration_token, expires_at.isoformat(), application_id)
            )
            conn.commit()
            conn.close()
        
        # Enviar email al conductor con link de registro
        email_sent = send_driver_approval_email(
            driver_email=application['email'],
            driver_name=application['full_name'],
            registration_token=registration_token,
            expires_at=expires_at.strftime("%d/%m/%Y a las %H:%M UTC")
        )
        
        return {
            "success": True,
            "message": f"Conductor {application['full_name']} aprobado exitosamente",
            "email_sent": email_sent,
            "registration_link_expires": expires_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error approving driver: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vlx/drivers/reject/{application_id}")
def reject_driver_application(application_id: str, token: str, reason: Optional[str] = "No se proporcionó razón"):
    """
    Endpoint para rechazar una aplicación de conductor desde el email del admin.
    """
    try:
        # Verificar que existe la aplicación y el token es válido
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .eq('approval_token', token)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found or invalid token")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE id = ? AND approval_token = ?",
                (application_id, token)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found or invalid token")
            
            application = {
                'id': row[0],
                'full_name': row[1],
                'status': row[-3]
            }
        
        # Verificar que está pendiente
        if application['status'] != 'pending':
            return {
                "success": False,
                "message": f"Esta aplicación ya fue {application['status']}",
                "status": application['status']
            }
        
        # Actualizar aplicación
        update_data = {
            'status': 'rejected',
            'rejected_at': datetime.utcnow().isoformat(),
            'rejection_reason': reason
        }
        
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update(update_data)\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE driver_applications 
                   SET status = ?, rejected_at = ?, rejection_reason = ?
                   WHERE id = ?""",
                ('rejected', datetime.utcnow().isoformat(), reason, application_id)
            )
            conn.commit()
            conn.close()
        
        return {
            "success": True,
            "message": f"Aplicación de {application['full_name']} rechazada",
            "reason": reason
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error rejecting driver: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Modelo para registro de conductor (set password)
class DriverPasswordSetup(BaseModel):
    token: str
    password: str


@app.post("/api/v1/auth/driver-set-password")
def driver_set_password(setup: DriverPasswordSetup):
    """
    Endpoint para que el conductor cree su contraseña usando el JWT token del email.
    Crea la cuenta de usuario y genera tokens de acceso automáticamente.
    """
    try:
        # Validar y decodificar JWT token
        try:
            payload = jwt.decode(setup.token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Verificar que sea un token de driver setup
            if payload.get('type') != 'driver_setup':
                raise HTTPException(status_code=400, detail="Token inválido")
            
            application_id = payload.get('application_id')
            email = payload.get('email')
            full_name = payload.get('full_name')
            
            if not all([application_id, email, full_name]):
                raise HTTPException(status_code=400, detail="Token inválido")
                
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=400, detail="Este enlace ha expirado. Por favor, solicita uno nuevo.")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=400, detail="Token inválido")
        
        # Verificar password mínimo 8 caracteres
        if len(setup.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        
        # Obtener la aplicación
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('id', application_id)\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM driver_applications WHERE id = ?", (application_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Application not found")
            
            application = {
                'id': row[0],
                'full_name': row[1],
                'email': row[2],
                'phone': row[3],
                'status': row[-7]
            }
        
        # Verificar que esté aprobada
        if application['status'] != 'approved':
            raise HTTPException(
                status_code=400,
                detail="Esta aplicación no está aprobada"
            )
        
        # Verificar si ya existe cuenta con ese email
        existing_user = None
        if USE_SUPABASE:
            existing = supabase_client.table('users')\
                .select('*')\
                .eq('email', email)\
                .execute()
            
            if existing.data:
                existing_user = existing.data[0]
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            if row:
                existing_user = dict(row)
            conn.close()
        
        # Si existe usuario, agregar rol "driver" a sus roles actuales
        if existing_user:
            print(f"✅ Usuario existente {email} - Agregando rol 'driver'")
            user_id = existing_user['id']
            
            # Obtener roles actuales
            current_roles = existing_user.get('roles', [])
            if isinstance(current_roles, str):
                try:
                    current_roles = json.loads(current_roles)
                except:
                    current_roles = []
            
            # Agregar "driver" a los roles (si no lo tiene)
            updated_roles = list(set(current_roles + ['driver']))
            
            # Obtener apps actuales
            current_apps = existing_user.get('allowed_apps', [])
            if isinstance(current_apps, str):
                try:
                    current_apps = json.loads(current_apps)
                except:
                    current_apps = ['vanelux']
            
            # Agregar "vanelux_driver"
            updated_apps = list(set(current_apps + ['vanelux', 'vanelux_driver']))
            
            # Hash de la nueva contraseña
            hashed_password = bcrypt.hashpw(setup.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Actualizar usuario: roles, apps, y contraseña
            if USE_SUPABASE:
                supabase_client.table('users').update({
                    'roles': updated_roles,
                    'allowed_apps': updated_apps,
                    'password_hash': hashed_password
                }).eq('id', user_id).execute()
            else:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET roles = ?, allowed_apps = ?, password_hash = ? WHERE id = ?",
                    (json.dumps(updated_roles), json.dumps(updated_apps), hashed_password, user_id)
                )
                conn.commit()
                conn.close()
            
            full_name = existing_user.get('full_name', full_name)
            username = existing_user.get('username', email.split('@')[0])
            
        else:
            # No existe usuario, crear uno nuevo
            print(f"✨ Creando nueva cuenta de driver para {email}")
            
            # Hash de la contraseña
            hashed_password = bcrypt.hashpw(setup.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Crear username del email (parte antes del @)
            username = email.split('@')[0]
            
            # Crear usuario usando create_user_db
            user = create_user_db(
                username=username,
                email=email,
                password_hash=hashed_password,
                full_name=full_name,
                roles=['driver'],
                allowed_apps=['vanelux', 'vanelux_driver']
            )
            
            user_id = user['id']
        
        # Actualizar aplicación a status "onboarded" y vincular user_id
        update_data = {
            'status': 'onboarded',
            'user_id': user_id,
            'setup_token': None  # Invalidar token
        }
        
        if USE_SUPABASE:
            supabase_client.table('driver_applications')\
                .update(update_data)\
                .eq('id', application_id)\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE driver_applications SET status = ?, user_id = ?, setup_token = NULL WHERE id = ?",
                ('onboarded', user_id, application_id)
            )
            conn.commit()
            conn.close()
        
        # Generar access token y refresh token
        access_token = create_access_token({
            'sub': str(user_id),
            'email': email,
            'roles': ['driver']
        })
        
        refresh_token, refresh_expires = create_refresh_token(user_id)
        save_refresh_token(user_id, refresh_token, refresh_expires)
        
        print(f"✅ Driver account created for {email} (user_id={user_id})")
        
        return {
            "success": True,
            "message": "¡Cuenta creada! Bienvenido a Vanelux.",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user_id,
                "email": email,
                "full_name": full_name,
                "username": username,
                "roles": ["driver"],
                "allowed_apps": ["vanelux", "vanelux_driver"],
                "status": "active"
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in driver set password: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# Modelo legacy para compatibilidad
class DriverRegistration(BaseModel):
    password: str
    username: Optional[str] = None

# Endpoint legacy - mantener por compatibilidad
@app.post("/api/v1/vlx/drivers/register")
def register_driver(token: str, registration: DriverRegistration):
    """
    Endpoint para que el conductor complete su registro con el token único.
    Crea cuenta en users con rol 'driver'.
    """
    try:
        # Buscar aplicación con el token de registro válido
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications')\
                .select('*')\
                .eq('registration_token', token)\
                .eq('status', 'approved')\
                .single()\
                .execute()
            
            if not result.data:
                raise HTTPException(status_code=404, detail="Invalid or expired registration token")
            
            application = result.data
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM driver_applications WHERE registration_token = ? AND status = 'approved'",
                (token,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                raise HTTPException(status_code=404, detail="Invalid or expired registration token")
            
            # Convertir a dict (asumiendo estructura)
            application = {'id': row[0], 'full_name': row[1], 'email': row[2], 'phone': row[3]}
        
        # Verificar que el token no haya expirado
        token_expires = datetime.fromisoformat(application['token_expires_at'].replace('Z', '+00:00'))
        if datetime.utcnow() > token_expires:
            raise HTTPException(status_code=400, detail="Registration token has expired")
        
        # Verificar que el usuario no exista ya
        if USE_SUPABASE:
            existing = supabase_client.table('users')\
                .select('id')\
                .eq('email', application['email'])\
                .execute()
            
            if existing.data:
                raise HTTPException(status_code=400, detail="User already exists")
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = ?", (application['email'],))
            if cursor.fetchone():
                conn.close()
                raise HTTPException(status_code=400, detail="User already exists")
            conn.close()
        
        # Hash de la contraseña
        hashed_password = bcrypt.hashpw(registration.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Crear username si no se proporcionó
        username = registration.username if registration.username else application['email'].split('@')[0]
        
        # Crear usuario en tabla users
        user_data = {
            'username': username,
            'email': application['email'],
            'full_name': application['full_name'],
            'password': hashed_password,
            'phone': application.get('phone', ''),
            'roles': ['driver'],
            'allowed_apps': ['vanelux', 'vanelux_driver'],
            'status': 'active',
            'created_at': datetime.utcnow().isoformat()
        }
        
        if USE_SUPABASE:
            user_result = supabase_client.table('users').insert(user_data).execute()
            
            if not user_result.data:
                raise HTTPException(status_code=500, detail="Failed to create user")
            
            user_id = user_result.data[0]['id']
            
            # Invalidar el token de registro (cambiar status a 'registered')
            supabase_client.table('driver_applications')\
                .update({'registration_token': None})\
                .eq('id', application['id'])\
                .execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO users (username, email, full_name, password, phone, roles, allowed_apps, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (username, application['email'], application['full_name'], hashed_password,
                 application.get('phone', ''), json.dumps(['driver']), json.dumps(['vanelux', 'vanelux_driver']),
                 'active', datetime.utcnow().isoformat())
            )
            user_id = cursor.lastrowid
            
            # Invalidar token
            cursor.execute(
                "UPDATE driver_applications SET registration_token = NULL WHERE id = ?",
                (application['id'],)
            )
            conn.commit()
            conn.close()
        
        return {
            "success": True,
            "message": "Registration completed successfully",
            "user_id": user_id,
            "username": username,
            "email": application['email']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in driver registration: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)