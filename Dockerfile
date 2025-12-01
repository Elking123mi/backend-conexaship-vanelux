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

# Comando de inicio usando Python para manejar el puerto
CMD ["python", "start_server.py"]
