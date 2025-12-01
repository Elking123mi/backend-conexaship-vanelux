FROM python:3.11-slim

WORKDIR /app

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Dar permisos de ejecución al script
RUN chmod +x start.sh

# Exponer puerto
EXPOSE 8000

# Comando de inicio usando el script bash
CMD ["./start.sh"]
