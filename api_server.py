"""
Backend REST API central para VaneLux y Conexaship
Endpoints de autenticación, usuarios, trips, payments
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import sqlite3
import jwt
import bcrypt
from datetime import datetime, timedelta
import json
import os

# Importar módulo de base de datos unificado
try:
    from backend.database import get_db_cursor, init_users_table as db_init_users_table
    USE_DB_MODULE = True
except ImportError:
    USE_DB_MODULE = False

app = FastAPI(title="Central Auth API", version="1.0.0")

# CORS para permitir Conexaship y VaneLux
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción: ["https://app.vanelux.tu", "https://app.conexaship.tu"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración
SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Path absoluto a la base de datos (en el directorio raíz del proyecto)
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "logistics.db"))

security = HTTPBearer()

# ==================== MODELOS ====================
class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: str  # Nombre completo de la persona
    roles: List[str] = ["worker"]
    allowed_apps: List[str] = ["vanelux", "conexaship"]  # Acceso a ambas apps por defecto

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str  # Nombre completo
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

class BookingResponse(BaseModel):
    id: int
    user_id: int
    pickup_address: str
    pickup_lat: Optional[float]
    pickup_lng: Optional[float]
    destination_address: str
    destination_lat: Optional[float]
    destination_lng: Optional[float]
    pickup_time: str
    vehicle_name: Optional[str]
    passengers: int
    price: float
    distance_miles: Optional[float]
    distance_text: Optional[str]
    duration_text: Optional[str]
    service_type: Optional[str]
    is_scheduled: bool
    status: str
    created_at: str
    updated_at: Optional[str]

# ==================== BASE DE DATOS ====================
def get_db():
    """Obtener conexión a base de datos (SQLite local o PostgreSQL en Railway)"""
    if USE_DB_MODULE:
        # Usar módulo database.py (soporta PostgreSQL)
        from backend.database import get_db as db_get_db
        conn, cursor_factory = db_get_db()
        return conn
    else:
        # Fallback a SQLite directo
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def init_users_table():
    """Crear tabla users si no existe"""
    if USE_DB_MODULE:
        # Usar función del módulo database.py
        db_init_users_table()
        return
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            roles TEXT DEFAULT '["worker"]',
            allowed_apps TEXT DEFAULT '["vanelux", "conexaship"]',
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Tabla de refresh tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    # Tabla de bookings VaneLux
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vlx_bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            origin TEXT NOT NULL,
            destination TEXT NOT NULL,
            pickup_time TEXT NOT NULL,
            passengers INTEGER DEFAULT 1,
            fare REAL NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

# ==================== JWT ====================
def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: int) -> tuple:
    """Retorna (token, expires_at_iso)"""
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
    """Dependency para extraer user desde access_token"""
    payload = verify_token(credentials.credentials, "access")
    return payload

# ==================== ENDPOINTS AUTH ====================
@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (req.username,))
    user_row = cur.fetchone()
    conn.close()
    
    if not user_row or not bcrypt.checkpw(req.password.encode(), user_row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user_id = user_row["id"]
    roles = json.loads(user_row["roles"])
    allowed_apps = json.loads(user_row["allowed_apps"])
    
    # Crear tokens
    access_token = create_access_token({
        "sub": str(user_id),
        "username": user_row["username"],
        "roles": roles,
        "allowed_apps": allowed_apps
    })
    refresh_token, expires_at = create_refresh_token(user_id)
    
    # Guardar refresh token en DB
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                (user_id, refresh_token, expires_at))
    conn.commit()
    conn.close()
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user_id,
            username=user_row["username"],
            email=user_row["email"],
            full_name=user_row["full_name"] if user_row["full_name"] else user_row["username"],
            roles=roles,
            allowed_apps=allowed_apps,
            status=user_row["status"]
        )
    )

@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
def refresh(req: RefreshRequest):
    payload = verify_token(req.refresh_token, "refresh")
    user_id = payload["sub"]
    
    # Validar que el refresh token no esté revocado
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0", (req.refresh_token,))
    token_row = cur.fetchone()
    if not token_row:
        conn.close()
        raise HTTPException(status_code=401, detail="Refresh token revoked or invalid")
    
    # Obtener usuario
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = cur.fetchone()
    conn.close()
    
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")
    
    roles = json.loads(user_row["roles"])
    allowed_apps = json.loads(user_row["allowed_apps"])
    
    # Crear nuevo access token (refresh token se mantiene)
    access_token = create_access_token({
        "sub": str(user_id),
        "username": user_row["username"],
        "roles": roles,
        "allowed_apps": allowed_apps
    })
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=req.refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user_id,
            username=user_row["username"],
            email=user_row["email"],
            full_name=user_row.get("full_name") or user_row["username"],
            roles=roles,
            allowed_apps=allowed_apps,
            status=user_row["status"]
        )
    )

@app.post("/api/v1/auth/logout")
def logout(req: RefreshRequest):
    """Revocar refresh token"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (req.refresh_token,))
    conn.commit()
    conn.close()
    return {"detail": "Logged out successfully"}

@app.post("/api/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    """Registro público de usuarios (no requiere autenticación)"""
    password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, email, password_hash, full_name, roles, allowed_apps)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user.username, user.email, password_hash, user.full_name,
              json.dumps(user.roles), json.dumps(user.allowed_apps)))
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    conn.close()
    
    return UserResponse(
        id=user_id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        roles=user.roles,
        allowed_apps=user.allowed_apps,
        status="active"
    )

@app.get("/api/v1/auth/me", response_model=UserResponse)
def get_me(current_user: dict = Depends(get_current_user)):
    """Retorna información del usuario actual"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (int(current_user["sub"]),))
    user_row = cur.fetchone()
    conn.close()
    
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        full_name=user_row["full_name"] if user_row.get("full_name") else user_row["username"],
        roles=json.loads(user_row["roles"]),
        allowed_apps=json.loads(user_row["allowed_apps"]),
        status=user_row["status"]
    )

# ==================== ENDPOINTS USERS ====================
@app.post("/api/v1/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, current_user: dict = Depends(get_current_user)):
    """Crear usuario (requiere permisos admin)"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, email, password_hash, full_name, roles, allowed_apps)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user.username, user.email, password_hash, user.full_name,
              json.dumps(user.roles), json.dumps(user.allowed_apps)))
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    conn.close()
    
    return UserResponse(
        id=user_id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        roles=user.roles,
        allowed_apps=user.allowed_apps,
        status="active"
    )



@app.get("/api/v1/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = cur.fetchone()
    conn.close()
    
    if not user_row:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        full_name=user_row.get("full_name") or user_row["username"],
        roles=json.loads(user_row["roles"]),
        allowed_apps=json.loads(user_row["allowed_apps"]),
        status=user_row["status"]
    )

@app.patch("/api/v1/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, 
                roles: Optional[List[str]] = None,
                allowed_apps: Optional[List[str]] = None,
                status: Optional[str] = None,
                current_user: dict = Depends(get_current_user)):
    """Actualizar usuario (requiere permisos admin)"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    conn = get_db()
    cur = conn.cursor()
    
    # Construir UPDATE dinámico
    updates = []
    params = []
    
    if roles is not None:
        updates.append("roles = ?")
        params.append(json.dumps(roles))
    
    if allowed_apps is not None:
        updates.append("allowed_apps = ?")
        params.append(json.dumps(allowed_apps))
    
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(user_id)
    
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    cur.execute(query, params)
    conn.commit()
    
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Obtener usuario actualizado
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_row = cur.fetchone()
    conn.close()
    
    return UserResponse(
        id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        full_name=user_row.get("full_name") or user_row["username"],
        roles=json.loads(user_row["roles"]),
        allowed_apps=json.loads(user_row["allowed_apps"]),
        status=user_row["status"]
    )

@app.delete("/api/v1/users/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """Soft delete - cambiar status a 'deleted' (requiere admin)"""
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET status = 'deleted', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
    conn.commit()
    
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    conn.close()
    return {"detail": "User deleted successfully"}

@app.get("/api/v1/users")
def list_users(email: Optional[str] = None):
    """Listar usuarios (SIN autenticación - público para que las apps puedan consultar)"""
    conn = get_db()
    cur = conn.cursor()
    
    if email:
        cur.execute("SELECT * FROM users WHERE email = ? AND status != 'deleted'", (email,))
        users = cur.fetchall()
    else:
        cur.execute("SELECT * FROM users WHERE status != 'deleted'")
        users = cur.fetchall()
    
    conn.close()
    
    users_list = [
        {
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "full_name": u["full_name"] if u["full_name"] else u["username"],
            "roles": json.loads(u["roles"]),
            "allowed_apps": json.loads(u["allowed_apps"]),
            "status": u["status"]
        } for u in users
    ]
    
    return {"users": users_list}

@app.get("/api/v1/users/check/{identifier}")
def check_user_exists(identifier: str):
    """Verificar si un usuario existe por email o username (SIN autenticación - público)"""
    conn = get_db()
    cur = conn.cursor()
    
    # Buscar por email o username
    cur.execute("""
        SELECT id, username, email, full_name, roles, allowed_apps, status 
        FROM users 
        WHERE (email = ? OR username = ?) AND status != 'deleted'
    """, (identifier, identifier))
    
    user_row = cur.fetchone()
    conn.close()
    
    if not user_row:
        return {
            "exists": False,
            "message": f"Usuario '{identifier}' no encontrado"
        }
    
    return {
        "exists": True,
        "user": {
            "id": user_row["id"],
            "username": user_row["username"],
            "email": user_row["email"],
            "full_name": user_row["full_name"] if user_row["full_name"] else user_row["username"],
            "roles": json.loads(user_row["roles"]),
            "allowed_apps": json.loads(user_row["allowed_apps"]),
            "status": user_row["status"]
        }
    }

# ==================== ENDPOINTS TRIPS (ejemplo) ====================
@app.get("/api/v1/trips")
def list_trips(current_user: dict = Depends(get_current_user)):
    """Placeholder para trips de Conexaship"""
    # TODO: implementar lógica real
    return {"trips": [], "message": "Trips endpoint placeholder"}

@app.post("/api/v1/trips")
def create_trip(current_user: dict = Depends(get_current_user)):
    """Placeholder para crear trip"""
    return {"detail": "Trip created (placeholder)"}

# ==================== ENDPOINTS PAYMENTS (ejemplo) ====================
@app.get("/api/v1/payments")
def list_payments(current_user: dict = Depends(get_current_user)):
    """Placeholder para payments"""
    return {"payments": [], "message": "Payments endpoint placeholder"}

# ==================== ENDPOINTS VANELUX BOOKINGS ====================
@app.post("/api/v1/vlx/bookings", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_booking(booking: BookingCreate, current_user: dict = Depends(get_current_user)):
    """Crear reserva de VaneLux"""
    # Validar que el usuario tenga acceso a VaneLux
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    # Validaciones de negocio
    if not booking.pickup_address or not booking.destination_address:
        raise HTTPException(status_code=400, detail="Pickup and destination addresses are required")
    
    if booking.price <= 0:
        raise HTTPException(status_code=400, detail="Price must be positive")
    
    if booking.passengers < 1:
        raise HTTPException(status_code=400, detail="Passengers must be at least 1")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vlx_bookings (
            user_id, pickup_address, pickup_lat, pickup_lng,
            destination_address, destination_lat, destination_lng,
            pickup_time, vehicle_name, passengers, price,
            distance_miles, distance_text, duration_text,
            service_type, is_scheduled, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        int(current_user["sub"]),
        booking.pickup_address,
        booking.pickup_lat,
        booking.pickup_lng,
        booking.destination_address,
        booking.destination_lat,
        booking.destination_lng,
        booking.pickup_time,
        booking.vehicle_name,
        booking.passengers,
        booking.price,
        booking.distance_miles,
        booking.distance_text,
        booking.duration_text,
        booking.service_type,
        1 if booking.is_scheduled else 0,
        booking.status
    ))
    conn.commit()
    booking_id = cur.lastrowid
    
    # Obtener la reserva creada
    cur.execute("SELECT * FROM vlx_bookings WHERE id = ?", (booking_id,))
    row = cur.fetchone()
    conn.close()
    
    return {
        "booking": {
            "id": row["id"],
            "user_id": row["user_id"],
            "pickup_address": row["pickup_address"],
            "pickup_lat": row["pickup_lat"],
            "pickup_lng": row["pickup_lng"],
            "destination_address": row["destination_address"],
            "destination_lat": row["destination_lat"],
            "destination_lng": row["destination_lng"],
            "pickup_time": row["pickup_time"],
            "vehicle_name": row["vehicle_name"],
            "passengers": row["passengers"],
            "price": row["price"],
            "distance_miles": row["distance_miles"],
            "distance_text": row["distance_text"],
            "duration_text": row["duration_text"],
            "service_type": row["service_type"],
            "is_scheduled": bool(row["is_scheduled"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        }
    }

@app.get("/api/v1/vlx/bookings")
def list_bookings(current_user: dict = Depends(get_current_user)):
    """Listar reservas del usuario actual"""
    try:
        print(f"🔵 GET bookings - Usuario: {current_user.get('username')}")
        print(f"🔵 allowed_apps: {current_user.get('allowed_apps')}")
        
        if "vanelux" not in current_user.get("allowed_apps", []):
            raise HTTPException(status_code=403, detail="Access to VaneLux required")
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM vlx_bookings WHERE user_id = ? ORDER BY created_at DESC", 
                    (int(current_user["sub"]),))
        rows = cur.fetchall()
        conn.close()
        
        print(f"🔵 Encontradas {len(rows)} reservas")
        
        bookings = []
        for row in rows:
            bookings.append({
                "id": row["id"],
                "user_id": row["user_id"],
                "pickup_address": row["pickup_address"],
                "pickup_lat": row["pickup_lat"],
                "pickup_lng": row["pickup_lng"],
                "destination_address": row["destination_address"],
                "destination_lat": row["destination_lat"],
                "destination_lng": row["destination_lng"],
                "pickup_time": row["pickup_time"],
                "vehicle_name": row["vehicle_name"],
                "passengers": row["passengers"],
                "price": row["price"],
                "distance_miles": row["distance_miles"],
                "distance_text": row["distance_text"],
                "duration_text": row["duration_text"],
                "service_type": row["service_type"],
                "is_scheduled": bool(row["is_scheduled"]),
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"]
            })
        
        print(f"✅ Devolviendo {len(bookings)} reservas")
        return {"bookings": bookings}
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"❌ ERROR en GET bookings: {e}")
        print(error_detail)
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@app.patch("/api/v1/vlx/bookings/{booking_id}")
def update_booking_status(booking_id: int, status: str, current_user: dict = Depends(get_current_user)):
    """Actualizar estado de reserva (confirmed, cancelled, completed)"""
    if "vanelux" not in current_user.get("allowed_apps", []):
        raise HTTPException(status_code=403, detail="Access to VaneLux required")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE vlx_bookings 
        SET status = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ?
    """, (status, booking_id, int(current_user["sub"])))
    conn.commit()
    
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Booking not found")
    
    conn.close()
    return {"detail": "Booking status updated", "status": status}

# ==================== STARTUP ====================
@app.on_event("startup")
def startup():
    init_users_table()
    # Crear usuario admin de ejemplo si no existe
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cur.fetchone():
        password_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        cur.execute("""
            INSERT INTO users (username, email, password_hash, roles, allowed_apps)
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", "admin@example.com", password_hash, 
              json.dumps(["admin", "manager"]), 
              json.dumps(["vanelux", "conexaship"])))
        conn.commit()
        print("✅ Usuario admin creado: admin / admin123")
    conn.close()

@app.get("/")
def root():
    return {"message": "Central Auth API", "version": "1.0.0", "docs": "/docs"}

if __name__ == "__main__":
    import uvicorn
    # Railway usa variable de entorno PORT
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)
