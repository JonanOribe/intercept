# Usamos una versión ligera de Python
FROM python:3.11-slim

# Evita que Python genere archivos .pyc y que el buffer se llene
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Primero instalamos solo las dependencias (Caché de capa)
COPY pyproject.toml requirements.txt* ./
RUN pip install --no-cache-dir pytest pytest-cov

# Copiamos el resto del código
COPY . .

# Comando por defecto para ejecutar los tests
CMD ["pytest", "--cov=.", "--cov-report=term-missing"]