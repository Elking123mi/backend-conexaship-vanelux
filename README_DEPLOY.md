# 🚀 Backend Conexaship & VaneLux

Backend centralizado con FastAPI + Supabase para las aplicaciones Conexaship y VaneLux.

## 📋 Características

- **FastAPI** - Framework web moderno y rápido
- **Supabase** - Base de datos PostgreSQL en la nube
- **JWT Authentication** - Autenticación segura con tokens
- **Multi-app** - Soporte para Conexaship y VaneLux
- **Railway Ready** - Configurado para despliegue automático

## 🔧 Configuración Local

1. Instalar dependencias:
```bash
pip install -r requirements.txt
```

2. Configurar variables de entorno (copiar `.env.example` a `.env`):
```
SUPABASE_URL=tu_url_de_supabase
SUPABASE_KEY=tu_clave_de_supabase
JWT_SECRET=tu_secreto_jwt
```

3. Ejecutar servidor:
```bash
uvicorn api_server_supabase:app --reload
```

## 🌐 Despliegue en Railway

Este proyecto está configurado para desplegarse automáticamente en Railway:

1. Conecta tu repositorio de GitHub con Railway
2. Configura las variables de entorno en Railway
3. Railway detectará `railway.json` y desplegará automáticamente

## 📚 Endpoints Principales

- `POST /auth/login` - Login con credenciales
- `POST /auth/login-card` - Login con tarjeta RFID
- `GET /auth/me` - Obtener usuario actual
- `POST /users/create-employee` - Crear nuevo empleado

## 🔐 Seguridad

- Contraseñas hasheadas con bcrypt
- Autenticación JWT
- Validación de `allowed_apps` por usuario
- CORS configurado

## 📦 Estructura

```
backend/
├── api_server_supabase.py    # Backend principal FastAPI
├── supabase_config.py         # Configuración de Supabase
├── requirements.txt           # Dependencias Python
├── railway.json              # Configuración Railway
├── Procfile                  # Comando de inicio
└── .env.example              # Variables de entorno de ejemplo
```

## 👥 Apps Soportadas

- **Conexaship** - Sistema de logística
- **VaneLux** - Sistema de taxis

---

**Desarrollado por Elkin Chila** 🚀
