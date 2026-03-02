"""
Endpoints para sistema de actualización automática
Agregar estos endpoints a api_server_supabase.py
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os

router = APIRouter()

# Configuración de versión actual
APP_VERSION = "1.0.0"  # Actualiza esto cada vez que subas nueva versión
DOWNLOAD_URL = "https://tu-servidor.com/downloads/LogisticsDashboard-v1.0.0.exe"
CHANGELOG = """
🎉 Versión 1.0.0
- ✅ Sistema de aplicaciones de conductores implementado
- ✅ Gestión de reservas web (bookings)
- ✅ Sistema de pagos integrado con Stripe
- ✅ Notificaciones por email automáticas
"""

class VersionInfo(BaseModel):
    version: str
    download_url: str
    changelog: str
    mandatory: bool = False  # Si True, obliga al usuario a actualizar
    size_mb: float = 0.0

@router.get("/api/v1/app/version")
async def get_latest_version():
    """
    Retorna información de la última versión disponible
    Las apps clientes consultarán este endpoint al iniciar
    """
    return {
        "version": APP_VERSION,
        "download_url": DOWNLOAD_URL,
        "changelog": CHANGELOG,
        "mandatory": False,  # Cambiar a True para forzar actualización
        "size_mb": 45.0  # Tamaño aproximado del .exe
    }

@router.get("/api/v1/app/check")
async def check_version(current_version: str):
    """
    Verifica si una versión específica necesita actualización
    
    Args:
        current_version: Versión actual del cliente (ej: "0.9.0")
    
    Returns:
        update_available: bool
        latest_version: str
    """
    from packaging import version as pkg_version
    
    is_outdated = pkg_version.parse(current_version) < pkg_version.parse(APP_VERSION)
    
    return {
        "update_available": is_outdated,
        "current_version": current_version,
        "latest_version": APP_VERSION,
        "changelog": CHANGELOG if is_outdated else None,
        "mandatory": False if not is_outdated else False
    }
