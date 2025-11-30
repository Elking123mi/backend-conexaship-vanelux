"""
Configuración de Supabase para el backend
"""
import os
from supabase import create_client, Client
from typing import Optional

# Credenciales de Supabase (obtener de dashboard)
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

# Cliente global de Supabase
supabase: Optional[Client] = None

def init_supabase():
    """Inicializar cliente de Supabase"""
    global supabase
    if SUPABASE_URL and SUPABASE_KEY:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        return supabase
    return None

def get_supabase() -> Optional[Client]:
    """Obtener cliente de Supabase"""
    global supabase
    if supabase is None:
        supabase = init_supabase()
    return supabase

# Funciones helper para operaciones comunes
class SupabaseDB:
    """Wrapper para operaciones de base de datos con Supabase"""
    
    @staticmethod
    def get_user_by_username(username: str):
        """Obtener usuario por username"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('users').select('*').eq('username', username).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def get_user_by_email(email: str):
        """Obtener usuario por email"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('users').select('*').eq('email', email).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def get_user_by_id(user_id: int):
        """Obtener usuario por ID"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('users').select('*').eq('id', user_id).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def create_user(username: str, email: str, password_hash: str, full_name: str, roles: list, allowed_apps: list):
        """Crear nuevo usuario"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('users').insert({
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'full_name': full_name,
            'roles': roles,
            'allowed_apps': allowed_apps,
            'status': 'active'
        }).execute()
        
        return response.data[0] if response.data else None
    
    @staticmethod
    def update_user(user_id: int, **kwargs):
        """Actualizar usuario"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('users').update(kwargs).eq('id', user_id).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def get_all_users():
        """Obtener todos los usuarios activos"""
        client = get_supabase()
        if not client:
            return []
        
        response = client.table('users').select('*').neq('status', 'deleted').execute()
        return response.data
    
    @staticmethod
    def create_refresh_token(user_id: int, token: str, expires_at: str):
        """Crear refresh token"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('refresh_tokens').insert({
            'user_id': user_id,
            'token': token,
            'expires_at': expires_at,
            'revoked': False
        }).execute()
        
        return response.data[0] if response.data else None
    
    @staticmethod
    def get_refresh_token(token: str):
        """Obtener refresh token"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('refresh_tokens').select('*').eq('token', token).eq('revoked', False).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def revoke_refresh_token(token: str):
        """Revocar refresh token"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('refresh_tokens').update({'revoked': True}).eq('token', token).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def create_booking(user_id: int, booking_data: dict):
        """Crear reserva de VaneLux"""
        client = get_supabase()
        if not client:
            return None
        
        data = {
            'user_id': user_id,
            **booking_data
        }
        
        response = client.table('vlx_bookings').insert(data).execute()
        return response.data[0] if response.data else None
    
    @staticmethod
    def get_user_bookings(user_id: int):
        """Obtener reservas de un usuario"""
        client = get_supabase()
        if not client:
            return []
        
        response = client.table('vlx_bookings').select('*').eq('user_id', user_id).order('created_at', desc=True).execute()
        return response.data
    
    @staticmethod
    def update_booking_status(booking_id: int, user_id: int, status: str):
        """Actualizar estado de reserva"""
        client = get_supabase()
        if not client:
            return None
        
        response = client.table('vlx_bookings').update({'status': status}).eq('id', booking_id).eq('user_id', user_id).execute()
        return response.data[0] if response.data else None
