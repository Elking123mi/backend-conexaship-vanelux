"""
Módulo de base de datos que soporta SQLite (local) y PostgreSQL (producción)
"""
import os
import sqlite3
from typing import Any
from contextlib import contextmanager

# Detectar si estamos en Railway o local
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # PRODUCCIÓN: PostgreSQL en Railway
    import psycopg2
    import psycopg2.extras
    from urllib.parse import urlparse
    
    def get_db():
        """Retorna conexión PostgreSQL"""
        url = urlparse(DATABASE_URL)
        conn = psycopg2.connect(
            host=url.hostname,
            database=url.path[1:],
            user=url.username,
            password=url.password,
            port=url.port
        )
        # Usar DictCursor para acceso por nombre de columna
        return conn, psycopg2.extras.DictCursor
    
    def init_users_table():
        """Crear tablas en PostgreSQL"""
        conn, cursor_factory = get_db()
        cur = conn.cursor(cursor_factory=cursor_factory)
        
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name VARCHAR(255),
                roles JSONB DEFAULT '["worker"]',
                allowed_apps JSONB DEFAULT '["vanelux", "conexaship"]',
                status VARCHAR(50) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Refresh tokens table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # VaneLux bookings table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vlx_bookings (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                pickup_address TEXT NOT NULL,
                pickup_lat DOUBLE PRECISION,
                pickup_lng DOUBLE PRECISION,
                destination_address TEXT NOT NULL,
                destination_lat DOUBLE PRECISION,
                destination_lng DOUBLE PRECISION,
                pickup_time VARCHAR(255) NOT NULL,
                vehicle_name VARCHAR(255),
                passengers INTEGER DEFAULT 1,
                price DOUBLE PRECISION NOT NULL,
                distance_miles DOUBLE PRECISION,
                distance_text VARCHAR(255),
                duration_text VARCHAR(255),
                service_type VARCHAR(50) DEFAULT 'standard',
                is_scheduled INTEGER DEFAULT 1,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        cur.close()
        conn.close()
        
else:
    # DESARROLLO: SQLite local
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "logistics.db")
    
    def get_db():
        """Retorna conexión SQLite"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn, None
    
    def init_users_table():
        """Crear tablas en SQLite"""
        conn, _ = get_db()
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
        
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vlx_bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                pickup_address TEXT NOT NULL,
                pickup_lat REAL,
                pickup_lng REAL,
                destination_address TEXT NOT NULL,
                destination_lat REAL,
                destination_lng REAL,
                pickup_time TEXT NOT NULL,
                vehicle_name TEXT,
                passengers INTEGER DEFAULT 1,
                price REAL NOT NULL,
                distance_miles REAL,
                distance_text TEXT,
                duration_text TEXT,
                service_type TEXT DEFAULT 'standard',
                is_scheduled INTEGER DEFAULT 1,
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        conn.commit()
        conn.close()

@contextmanager
def get_db_cursor():
    """Context manager para manejar conexiones de forma segura"""
    conn, cursor_factory = get_db()
    try:
        if cursor_factory:
            # PostgreSQL
            cur = conn.cursor(cursor_factory=cursor_factory)
        else:
            # SQLite
            cur = conn.cursor()
        yield conn, cur
    finally:
        conn.close()
