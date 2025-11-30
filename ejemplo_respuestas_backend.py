"""
EJEMPLO RÁPIDO: Respuestas que el backend debe retornar
para que Conexaship y VaneLux funcionen correctamente
"""

# ==================== POST /api/v1/auth/login ====================
# REQUEST:
{
    "username": "admin",
    "password": "admin123"
}

# RESPONSE (200 OK):
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["admin", "manager"],
        "allowed_apps": ["vanelux", "conexaship"],
        "status": "active"
    }
}

# ==================== POST /api/v1/auth/refresh ====================
# REQUEST:
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# RESPONSE (200 OK):
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  # NUEVO
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  # MISMO
    "expires_in": 3600,
    "user": {
        "id": 1,
        "username": "admin",
        "email": "admin@example.com",
        "roles": ["admin", "manager"],
        "allowed_apps": ["vanelux", "conexaship"],
        "status": "active"
    }
}

# ==================== POST /api/v1/auth/logout ====================
# REQUEST:
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

# RESPONSE (200 OK):
{
    "detail": "Logged out successfully"
}

# ==================== GET /api/v1/auth/me ====================
# HEADERS:
# Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# RESPONSE (200 OK):
{
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "roles": ["admin", "manager"],
    "allowed_apps": ["vanelux", "conexaship"],
    "status": "active"
}

# ==================== GET /api/v1/trips ====================
# HEADERS:
# Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# RESPONSE (200 OK):
{
    "trips": [
        {
            "id": 1,
            "origin": "Ciudad A",
            "destination": "Ciudad B",
            "driver_id": 5,
            "status": "en_progreso",
            "created_at": "2025-11-19T10:30:00Z"
        }
    ]
}

# ==================== POST /api/v1/trips ====================
# HEADERS:
# Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# REQUEST:
{
    "origin": "Ciudad A",
    "destination": "Ciudad B",
    "driver_id": 5,
    "cargo_description": "Productos varios"
}

# RESPONSE (201 CREATED):
{
    "id": 2,
    "origin": "Ciudad A",
    "destination": "Ciudad B",
    "driver_id": 5,
    "status": "pendiente",
    "cargo_description": "Productos varios",
    "created_at": "2025-11-19T15:45:00Z"
}

# ==================== ERRORES COMUNES ====================

# 401 Unauthorized (token inválido o expirado):
{
    "detail": "Invalid token"
}

# 403 Forbidden (sin permisos):
{
    "detail": "Admin role required"
}

# 404 Not Found:
{
    "detail": "User not found"
}

# 400 Bad Request:
{
    "detail": "Username or email already exists"
}
