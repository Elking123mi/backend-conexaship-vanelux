FROM python:3.11-slim

WORKDIR /app

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Exponer puerto
EXPOSE 8000

# Comando de inicio - Railway pasará el puerto como variable de entorno
CMD uvicorn api_server_supabase:app --host 0.0.0.0 --port ${PORT:-8000}
