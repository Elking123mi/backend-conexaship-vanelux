#!/bin/bash
# Script de inicio para Railway

# Railway pasa PORT como variable de entorno
# Si no existe, usar 8000 por defecto
PORT=${PORT:-8000}

echo "Starting server on port $PORT"
exec uvicorn api_server_supabase:app --host 0.0.0.0 --port $PORT
