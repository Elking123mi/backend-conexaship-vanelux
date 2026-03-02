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

# ─── REAL-TIME TRACKING (in-memory, per-process) ─────────────────────────────
# { booking_id: { lat, lng, status, updated_at, driver_name, driver_phone, vehicle } }
driver_locations: dict = {}

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

class DriverLocationUpdate(BaseModel):
    lat: float
    lng: float
    status: Optional[str] = None  # en_route_to_pickup | arrived_at_pickup | in_progress | completed

class TripRating(BaseModel):
    rating: int           # 1-5
    comment: Optional[str] = ""


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

# ==================== AUTO-ACTUALIZACIÓN ====================
APP_VERSION = "1.0.1"  # Versión actual de la aplicación de escritorio
APP_DOWNLOAD_URL = "https://github.com/Elking123mi/backend-conexaship-vanelux/releases/download/v1.0.1/LogisticsDashboard-v1.0.1.exe"
APP_CHANGELOG = """🎉 Versión 1.0.0

✅ Funcionalidades actuales:
- Sistema de aplicaciones de conductores implementado
- Panel de gestión de reservas web (bookings)
- Sistema de pagos integrado con Stripe
- Notificaciones automáticas por email
- Auto-actualización automática integrada

🐛 Correcciones:
- Mejora en validación de tarjetas CCID
- Optimización de conexión con Supabase

⚡ Mejoras de rendimiento:
- Carga más rápida de datos
- Interfaz más responsiva
"""

@app.get("/api/v1/app/version")
def get_app_version():
    """
    Endpoint para verificar la última versión disponible de la aplicación
    Las apps clientes consultan este endpoint al iniciar para verificar actualizaciones
    """
    return {
        "version": APP_VERSION,
        "download_url": APP_DOWNLOAD_URL,
        "changelog": APP_CHANGELOG,
        "mandatory": False,  # Si es True, la app obliga a actualizar
        "size_mb": 60.0,  # Tamaño aproximado del ejecutable
        "release_date": "2026-02-26"
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


# ─── REAL-TIME TRACKING ENDPOINTS ───────────────────────────────────────────

@app.put("/api/v1/vlx/bookings/{booking_id}/driver-location")
def update_driver_location(
    booking_id: int,
    location: DriverLocationUpdate,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    El driver actualiza su posición GPS y estado del viaje.
    Llama cada 5 segundos desde la app del driver.
    """
    token_data = verify_token(credentials.credentials)
    if "vanelux" not in token_data.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access denied")

    # Obtener info del driver para mostrársela al cliente
    try:
        if USE_SUPABASE:
            booking_resp = supabase_client.table("vlx_bookings").select("*").eq("id", booking_id).execute()
            booking = booking_resp.data[0] if booking_resp.data else {}
        else:
            booking = {}
    except Exception:
        booking = {}

    # Actualizar location en memoria
    driver_locations[str(booking_id)] = {
        "lat": location.lat,
        "lng": location.lng,
        "status": location.status or driver_locations.get(str(booking_id), {}).get("status", "en_route_to_pickup"),
        "updated_at": datetime.utcnow().isoformat(),
        "driver_id": token_data.get("sub")
    }

    # Si se actualiza el status, también actualizar en la DB
    if location.status and USE_SUPABASE:
        try:
            update_data = {"status": location.status, "updated_at": datetime.utcnow().isoformat()}
            if location.status == "in_progress":
                update_data["started_at"] = datetime.utcnow().isoformat()
            elif location.status == "completed":
                update_data["completed_at"] = datetime.utcnow().isoformat()
            supabase_client.table("vlx_bookings").update(update_data).eq("id", booking_id).execute()
        except Exception as e:
            print(f"⚠️ Could not update booking status in DB: {e}")

        # Email automático al cliente cuando el driver sale a buscarlo
        if location.status in ("en_route_to_pickup", "arrived_at_pickup") and booking:
            try:
                client_email = booking.get("guest_email")
                client_name = f"{booking.get('guest_first_name', '')} {booking.get('guest_last_name', '')}".strip() or "Valued Client"
                pickup_addr = booking.get("pickup_address", "your pickup location")
                vehicle = booking.get("vehicle_name", "your vehicle")
                if client_email:
                    _send_driver_status_email(
                        to_email=client_email,
                        client_name=client_name,
                        status=location.status,
                        pickup_address=pickup_addr,
                        vehicle_name=vehicle,
                        booking_id=booking_id
                    )
            except Exception as mail_err:
                print(f"⚠️ Status email error: {mail_err}")

    return {"success": True, "message": "Location updated"}


@app.get("/api/v1/vlx/bookings/{booking_id}/tracking")
def get_trip_tracking(
    booking_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    El cliente consulta la posición en tiempo real del driver.
    Hace polling cada 5 segundos.
    """
    verify_token(credentials.credentials)

    try:
        if USE_SUPABASE:
            booking_resp = supabase_client.table("vlx_bookings").select("*").eq("id", booking_id).execute()
            if not booking_resp.data:
                raise HTTPException(status_code=404, detail="Booking not found")
            booking = booking_resp.data[0]
        else:
            raise HTTPException(status_code=404, detail="Booking not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    location_data = driver_locations.get(str(booking_id))

    # Intentar obtener info del driver asignado
    driver_info = None
    if booking.get("driver_id") and USE_SUPABASE:
        try:
            driver_resp = supabase_client.table("users").select("full_name,email,phone").eq("id", booking["driver_id"]).execute()
            if driver_resp.data:
                driver_info = driver_resp.data[0]
        except Exception:
            pass

    return {
        "booking_id": booking_id,
        "booking_status": booking.get("status", "pending"),
        "pickup_address": booking.get("pickup_address", ""),
        "pickup_lat": booking.get("pickup_lat"),
        "pickup_lng": booking.get("pickup_lng"),
        "destination_address": booking.get("destination_address", ""),
        "destination_lat": booking.get("destination_lat"),
        "destination_lng": booking.get("destination_lng"),
        "pickup_time": booking.get("pickup_time", ""),
        "vehicle_name": booking.get("vehicle_name", ""),
        "driver": driver_info,
        "driver_location": location_data,
        "tracking_active": location_data is not None and (
            datetime.utcnow() - datetime.fromisoformat(location_data["updated_at"])
        ).seconds < 30  # Activo si se actualizó en los últimos 30 segundos
    }


# ==================== CALIFICACIONES / RATINGS ====================

@app.post("/api/v1/vlx/bookings/{booking_id}/rate")
def rate_trip(
    booking_id: int,
    rating_data: TripRating,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Cliente califica el viaje (1-5 estrellas + comentario)."""
    payload = verify_token(credentials.credentials)
    user_id = payload.get("user_id") or payload.get("sub")

    if not (1 <= rating_data.rating <= 5):
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    if not USE_SUPABASE:
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        booking_resp = supabase_client.table("vlx_bookings").select("id,driver_id,status,guest_email").eq("id", booking_id).execute()
        if not booking_resp.data:
            raise HTTPException(status_code=404, detail="Booking not found")

        booking = booking_resp.data[0]
        if booking.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Can only rate completed trips")

        # Upsert para evitar duplicados
        supabase_client.table("trip_ratings").upsert({
            "booking_id": booking_id,
            "driver_id": booking.get("driver_id"),
            "user_id": user_id,
            "rating": rating_data.rating,
            "comment": rating_data.comment or "",
            "created_at": datetime.utcnow().isoformat()
        }, on_conflict="booking_id").execute()

        return {"success": True, "message": "Thank you for your rating!"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vlx/drivers/{driver_id}/ratings")
def get_driver_ratings(
    driver_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Devuelve el promedio y lista de calificaciones de un driver."""
    verify_token(credentials.credentials)

    if not USE_SUPABASE:
        return {"average": 0, "count": 0, "ratings": []}

    try:
        resp = supabase_client.table("trip_ratings").select("*").eq("driver_id", driver_id).order("created_at", desc=True).execute()
        ratings = resp.data or []
        avg = round(sum(r["rating"] for r in ratings) / len(ratings), 2) if ratings else 0
        return {"driver_id": driver_id, "average": avg, "count": len(ratings), "ratings": ratings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vlx/bookings/{booking_id}/rating")
def get_booking_rating(
    booking_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Devuelve la calificación de un booking específico (si existe)."""
    verify_token(credentials.credentials)
    if not USE_SUPABASE:
        return None
    try:
        resp = supabase_client.table("trip_ratings").select("*").eq("booking_id", booking_id).execute()
        return resp.data[0] if resp.data else None
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

def send_driver_application_email(application_data: dict, application_id: str):
    """
    Envía email al admin con los datos de la aplicación del conductor usando Mailgun API.
    """
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@vanelux.com')
    
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
        
        # Enviar email al admin
        email_sent = False
        try:
            email_sent = send_driver_application_email(
                application_data=application.dict(),
                application_id=str(application_id)
            )
        except Exception as email_error:
            print(f"⚠️ Failed to send email: {email_error}")
            # No fallar el request si el email falla

        # Enviar email de confirmación al conductor
        try:
            _send_driver_confirmation_email(
                to_email=application.email,
                driver_name=application.full_name
            )
        except Exception as email_error:
            print(f"⚠️ Failed to send confirmation email to driver: {email_error}")
        
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


# ─── DRIVER APPLICATIONS ADMIN ────────────────────────────────────────────────

class DriverApprovalRequest(BaseModel):
    admin_note: Optional[str] = ""


@app.get("/api/v1/vlx/drivers/applications")
def list_driver_applications(
    status_filter: Optional[str] = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Lista todas las aplicaciones de conductores.
    Requiere rol admin/manager/ceo.
    Filtra por status: pending | approved | rejected | onboarded
    """
    payload = verify_token(credentials.credentials)
    roles = payload.get("roles", [])
    # Normalizar roles a minúsculas para comparación (acepta CEO, ceo, Manager, manager, etc.)
    normalized_roles = [str(r).lower() for r in roles]
    if not any(r in normalized_roles for r in ["admin", "manager", "ceo", "executive"]):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        if USE_SUPABASE:
            query = supabase_client.table('driver_applications').select('*').order('created_at', desc=True)
            if status_filter:
                query = query.eq('status', status_filter)
            result = query.execute()
            return {"success": True, "applications": result.data, "total": len(result.data)}
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if status_filter:
                cursor.execute("SELECT * FROM driver_applications WHERE status=? ORDER BY created_at DESC", (status_filter,))
            else:
                cursor.execute("SELECT * FROM driver_applications ORDER BY created_at DESC")
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"success": True, "applications": rows, "total": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/drivers/applications/{application_id}/approve")
def approve_driver_application(
    application_id: str,
    body: DriverApprovalRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Aprueba una aplicación de conductor.
    - Cambia status a 'approved'
    - Genera token de setup (72h)
    - Envía email al conductor con enlace para crear su contraseña
    """
    payload = verify_token(credentials.credentials)
    roles = payload.get("roles", [])
    # Normalizar roles a minúsculas para comparación (acepta CEO, ceo, Manager, manager, etc.)
    normalized_roles = [str(r).lower() for r in roles]
    if not any(r in normalized_roles for r in ["admin", "manager", "ceo", "executive"]):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        # 1. Obtener la aplicación
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications').select('*').eq('id', application_id).execute()
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            app_data = result.data[0]
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM driver_applications WHERE id=?", (application_id,))
            row = cursor.fetchone()
            conn.close()
            if not row:
                raise HTTPException(status_code=404, detail="Application not found")
            app_data = dict(row)

        if app_data['status'] == 'approved':
            raise HTTPException(status_code=400, detail="Application already approved")

        # 2. Generar token de setup (expira en 72 horas)
        setup_token_payload = {
            "type": "driver_setup",
            "application_id": application_id,
            "email": app_data['email'],
            "full_name": app_data['full_name'],
            "exp": datetime.utcnow() + timedelta(hours=72)
        }
        setup_token = jwt.encode(setup_token_payload, SECRET_KEY, algorithm=ALGORITHM)

        # 3. Actualizar status en BD
        update_data = {
            "status": "approved",
            "admin_note": body.admin_note,
            "setup_token": setup_token,
            "approved_at": datetime.utcnow().isoformat()
        }
        if USE_SUPABASE:
            supabase_client.table('driver_applications').update(update_data).eq('id', application_id).execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE driver_applications SET status='approved', admin_note=?, setup_token=?, approved_at=? WHERE id=?",
                (body.admin_note, setup_token, datetime.utcnow().isoformat(), application_id)
            )
            conn.commit()
            conn.close()

        # 4. Enviar email al conductor con el enlace
        app_base_url = os.getenv("APP_BASE_URL", "https://vanelux.netlify.app")
        setup_link = f"{app_base_url}/#/set-password?token={setup_token}"

        email_sent = _send_approval_email(
            to_email=app_data['email'],
            driver_name=app_data['full_name'],
            setup_link=setup_link,
            admin_note=body.admin_note or ""
        )

        print(f"✅ Application {application_id} approved. Email sent: {email_sent}")
        return {
            "success": True,
            "message": f"Application approved. Setup email sent to {app_data['email']}",
            "email_sent": email_sent,
            "setup_link": setup_link
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vlx/drivers/applications/{application_id}/reject")
def reject_driver_application(
    application_id: str,
    body: DriverApprovalRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Rechaza una aplicación y notifica al conductor por email."""
    payload = verify_token(credentials.credentials)
    roles = payload.get("roles", [])
    # Normalizar roles a minúsculas para comparación (acepta CEO, ceo, Manager, manager, etc.)
    normalized_roles = [str(r).lower() for r in roles]
    if not any(r in normalized_roles for r in ["admin", "manager", "ceo", "executive"]):
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        if USE_SUPABASE:
            result = supabase_client.table('driver_applications').select('*').eq('id', application_id).execute()
            if not result.data:
                raise HTTPException(status_code=404, detail="Application not found")
            app_data = result.data[0]
            supabase_client.table('driver_applications').update({
                "status": "rejected",
                "admin_note": body.admin_note
            }).eq('id', application_id).execute()
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM driver_applications WHERE id=?", (application_id,))
            row = cursor.fetchone()
            if not row:
                conn.close()
                raise HTTPException(status_code=404, detail="Application not found")
            app_data = dict(row)
            cursor.execute(
                "UPDATE driver_applications SET status='rejected', admin_note=? WHERE id=?",
                (body.admin_note, application_id)
            )
            conn.commit()
            conn.close()

        _send_rejection_email(
            to_email=app_data['email'],
            driver_name=app_data['full_name'],
            reason=body.admin_note or ""
        )
        return {"success": True, "message": "Application rejected"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/auth/driver-set-password")
def driver_set_password(request: dict):
    """
    El conductor nuevo crea su contraseña usando el token del email de aprobación.
    Crea la cuenta de usuario con rol driver y retorna token de acceso.
    """
    token = request.get("token")
    password = request.get("password")

    if not token or not password:
        raise HTTPException(status_code=400, detail="token and password are required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Este enlace ha expirado. Contacta a Vanelux para recibir uno nuevo.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido.")

    if payload.get("type") != "driver_setup":
        raise HTTPException(status_code=400, detail="Token tipo incorrecto")

    application_id = payload["application_id"]
    email = payload["email"]
    full_name = payload["full_name"]

    # Verificar que la aplicación esté aprobada
    if USE_SUPABASE:
        result = supabase_client.table('driver_applications').select('*').eq('id', application_id).execute()
        if not result.data or result.data[0]['status'] not in ('approved',):
            raise HTTPException(status_code=400, detail="Application not found or not in approved state")
        app_data = result.data[0]

        # Verificar que no exista ya una cuenta
        existing = supabase_client.table('users').select('id').eq('email', email).execute()
        if existing.data:
            raise HTTPException(status_code=400, detail="Ya existe una cuenta con este email. Inicia sesión.")
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM driver_applications WHERE id=? AND status='approved'", (application_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=400, detail="Application not found or not approved")
        app_data = dict(row)

    # Crear cuenta de usuario con rol driver
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    username = email.split('@')[0].lower().replace('.', '_').replace('+', '_')

    new_user = {
        "username": username,
        "email": email,
        "password_hash": hashed_password,
        "full_name": full_name,
        "roles": ["driver"],
        "allowed_apps": ["vanelux", "vanelux_driver"],
        "status": "active"
    }

    if USE_SUPABASE:
        user_result = supabase_client.table('users').insert(new_user).execute()
        if not user_result.data:
            raise HTTPException(status_code=500, detail="Failed to create user account")
        user_id = user_result.data[0]['id']

        # Marcar aplicación como onboarded e invalidar token
        supabase_client.table('driver_applications').update({
            "status": "onboarded",
            "user_id": user_id,
            "setup_token": None
        }).eq('id', application_id).execute()
    else:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, full_name, roles, allowed_apps, status) VALUES (?,?,?,?,?,?,?)",
            (username, email, hashed_password, full_name, json.dumps(["driver"]), json.dumps(["vanelux", "vanelux_driver"]), "active")
        )
        user_id = cursor.lastrowid
        cursor.execute("UPDATE driver_applications SET status='onboarded', user_id=? WHERE id=?", (user_id, application_id))
        conn.commit()
        conn.close()

    # Generar tokens de acceso para inicio de sesión inmediato
    access_token = create_access_token({"sub": str(user_id), "email": email, "roles": ["driver"]})
    refresh_token = create_access_token(
        {"sub": str(user_id), "email": email, "type": "refresh"},
        expires_delta=timedelta(days=30)
    )

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


def _send_driver_status_email(to_email: str, client_name: str, status: str,
                              pickup_address: str, vehicle_name: str, booking_id: int) -> bool:
    """Email automático al cliente cuando el driver marca en_route o arrived."""
    mailgun_key = os.getenv('MAILGUN_API_KEY', '')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
    from_email = os.getenv('MAILGUN_FROM_EMAIL', f'noreply@{mailgun_domain}')
    if not mailgun_key or not mailgun_domain:
        return False

    if status == "en_route_to_pickup":
        subject = "🚗 Your Vanelux driver is on the way!"
        headline = "Your driver is heading to you"
        message = f"Your Vanelux driver is now <strong>on the way</strong> to pick you up at:<br><strong>{pickup_address}</strong>"
        cta = "Please be ready in the next few minutes."
        icon = "🚗"
        color = "#8B5CF6"
    else:  # arrived_at_pickup
        subject = "📍 Your driver has arrived — Vanelux"
        headline = "Your driver has arrived!"
        message = f"Your Vanelux driver is <strong>waiting for you</strong> at:<br><strong>{pickup_address}</strong>"
        cta = "Please come out now. Your vehicle is: <strong>{}</strong>".format(vehicle_name)
        icon = "📍"
        color = "#10B981"

    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#333;margin:0;padding:0">
      <div style="background:#0B3254;color:white;padding:40px;text-align:center">
        <div style="font-size:48px">{icon}</div>
        <h1 style="margin:10px 0">{headline}</h1>
        <p style="color:#D4AF37;margin:0">Booking #{booking_id}</p>
      </div>
      <div style="padding:30px;max-width:600px;margin:0 auto">
        <p>Dear <strong>{client_name}</strong>,</p>
        <div style="background:{color}15;border-left:4px solid {color};padding:16px;border-radius:4px;margin:20px 0">
          <p style="margin:0;font-size:16px">{message}</p>
        </div>
        <p>{cta}</p>
        <p>If you need help: 📞 <a href="tel:+19175995522" style="color:#0B3254">+1 (917) 599-5522</a> &nbsp;|
           💬 <a href="https://wa.me/19175995522" style="color:#25D366">WhatsApp</a></p>
      </div>
      <div style="background:#f4f4f4;padding:15px;text-align:center;color:#888;font-size:12px">
        Vanelux Luxury Transportation — New York City
      </div>
    </body></html>
    """
    try:
        resp = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_key),
            data={"from": f"Vanelux <{from_email}>", "to": [to_email], "subject": subject, "html": html}
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"⚠️ Driver status email error: {e}")
        return False


def _send_driver_confirmation_email(to_email: str, driver_name: str) -> bool:
    """Envía email de confirmación al conductor cuando envía su aplicación."""
    mailgun_key = os.getenv('MAILGUN_API_KEY', '')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
    from_email = os.getenv('MAILGUN_FROM_EMAIL', f'noreply@{mailgun_domain}')

    if not mailgun_key or not mailgun_domain:
        print("⚠️ Mailgun not configured, skipping driver confirmation email")
        return False

    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#333;margin:0;padding:0">
      <div style="background:#0B3254;color:white;padding:40px;text-align:center">
        <h1 style="margin:0">Thank you, {driver_name}!</h1>
        <p style="color:#D4AF37;font-size:18px;margin:10px 0 0">We received your Vanelux driver application</p>
      </div>
      <div style="padding:30px;max-width:600px;margin:0 auto">
        <p>Dear <strong>{driver_name}</strong>,</p>
        <p>We have successfully received your application to join the <strong>Vanelux luxury driver team</strong>. 🎉</p>
        <p>Our team will carefully review your information and get back to you within <strong>2–5 business days</strong>.</p>
        <div style="background:#f8f9fa;border-left:4px solid #D4AF37;padding:16px;margin:24px 0;border-radius:4px">
          <strong>What happens next?</strong><br>
          <ol style="margin:10px 0;padding-left:20px">
            <li>Our team reviews your application</li>
            <li>If approved, you will receive an email with a <strong>one-time link</strong> to create your driver account</li>
            <li>You set your own password and you're ready to go!</li>
          </ol>
        </div>
        <p>If you have any questions in the meantime, feel free to reach out:</p>
        <p>📞 <a href="tel:+19175995522" style="color:#0B3254">+1 (917) 599-5522</a><br>
           ✉️ <a href="mailto:info@vanelux.com" style="color:#0B3254">info@vanelux.com</a><br>
           💬 <a href="https://wa.me/19175995522" style="color:#25D366">WhatsApp</a></p>
      </div>
      <div style="background:#f4f4f4;padding:15px;text-align:center;color:#888;font-size:12px">
        Vanelux Luxury Transportation — New York City<br>
        📞 +1 (917) 599-5522 | ✉️ info@vanelux.com
      </div>
    </body></html>
    """

    try:
        resp = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_key),
            data={
                "from": f"Vanelux <{from_email}>",
                "to": [to_email],
                "subject": "✅ We received your Vanelux driver application",
                "html": html
            }
        )
        success = resp.status_code == 200
        if not success:
            print(f"⚠️ Mailgun confirmation error {resp.status_code}: {resp.text}")
        return success
    except Exception as e:
        print(f"⚠️ Driver confirmation email error: {e}")
        return False


def _send_approval_email(to_email: str, driver_name: str, setup_link: str, admin_note: str) -> bool:
    """Envía email de aprobación al conductor con enlace para crear contraseña."""
    mailgun_key = os.getenv('MAILGUN_API_KEY', '')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
    from_email = os.getenv('MAILGUN_FROM_EMAIL', f'noreply@{mailgun_domain}')

    if not mailgun_key or not mailgun_domain:
        print("⚠️ Mailgun not configured, skipping approval email")
        return False

    note_html = (
        f'<p style="background:#fff3cd;padding:12px;border-left:4px solid #ffc107">'
        f'<strong>Note from Vanelux:</strong> {admin_note}</p>'
    ) if admin_note else ''

    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#333;margin:0;padding:0">
      <div style="background:#0B3254;color:white;padding:40px;text-align:center">
        <h1 style="margin:0">🎉 Congratulations, {driver_name}!</h1>
        <p style="color:#D4AF37;font-size:18px;margin:10px 0 0">Your Vanelux driver application has been <strong>approved</strong></p>
      </div>
      <div style="padding:30px;max-width:600px;margin:0 auto">
        {note_html}
        <p>You are now one step away from joining the <strong>Vanelux luxury driver team</strong>.</p>
        <p>Click the button below to <strong>create your password</strong> and activate your driver account:</p>
        <div style="text-align:center;margin:35px 0">
          <a href="{setup_link}"
             style="background:#D4AF37;color:#0B3254;padding:18px 44px;text-decoration:none;
                    border-radius:8px;font-weight:bold;font-size:17px;display:inline-block">
            ✅ Create My Password
          </a>
        </div>
        <p style="color:#888;font-size:13px">⏰ This link expires in <strong>72 hours</strong>.</p>
        <p style="color:#888;font-size:13px">If the button doesn't work, copy and paste this link into your browser:<br>
          <a href="{setup_link}" style="color:#0B3254;word-break:break-all">{setup_link}</a>
        </p>
      </div>
      <div style="background:#f4f4f4;padding:15px;text-align:center;color:#888;font-size:12px">
        Vanelux Luxury Transportation — New York City<br>
        📞 +1 (917) 599-5522 | ✉️ info@vanelux.com
      </div>
    </body></html>
    """

    try:
        resp = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_key),
            data={
                "from": f"Vanelux <{from_email}>",
                "to": [to_email],
                "subject": "🎉 Your Vanelux Driver Application is Approved — Create Your Password",
                "html": html
            }
        )
        success = resp.status_code == 200
        if not success:
            print(f"⚠️ Mailgun error {resp.status_code}: {resp.text}")
        return success
    except Exception as e:
        print(f"⚠️ Approval email error: {e}")
        return False


def _send_rejection_email(to_email: str, driver_name: str, reason: str) -> bool:
    """Envía email de rechazo al conductor."""
    mailgun_key = os.getenv('MAILGUN_API_KEY', '')
    mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
    from_email = os.getenv('MAILGUN_FROM_EMAIL', f'noreply@{mailgun_domain}')

    if not mailgun_key or not mailgun_domain:
        return False

    reason_html = (
        f'<p style="background:#fdecea;padding:12px;border-left:4px solid #e53935">'
        f'<strong>Reason:</strong> {reason}</p>'
    ) if reason else ''

    html = f"""
    <html><body style="font-family:Arial,sans-serif;color:#333">
      <div style="background:#0B3254;color:white;padding:30px;text-align:center">
        <h1>Vanelux Driver Application Update</h1>
      </div>
      <div style="padding:30px;max-width:600px;margin:0 auto">
        <p>Dear {driver_name},</p>
        <p>Thank you for your interest in joining the Vanelux driver team.
           After reviewing your application, we are unable to move forward at this time.</p>
        {reason_html}
        <p>You are welcome to reapply in the future. If you have questions, please contact us:</p>
        <p>📞 <a href="tel:+19175995522">+1 (917) 599-5522</a><br>
           ✉️ <a href="mailto:info@vanelux.com">info@vanelux.com</a></p>
      </div>
      <div style="background:#f4f4f4;padding:15px;text-align:center;color:#888;font-size:12px">
        Vanelux Luxury Transportation — New York City
      </div>
    </body></html>
    """

    try:
        resp = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_key),
            data={
                "from": f"Vanelux <{from_email}>",
                "to": [to_email],
                "subject": "Vanelux Driver Application — Status Update",
                "html": html
            }
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"⚠️ Rejection email error: {e}")
        return False


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)
