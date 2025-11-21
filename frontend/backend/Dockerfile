FROM python:3.11-slim

# Install system dependencies (keytool requires JRE, openssl for crypto)
RUN apt-get update && apt-get install -y \
    default-jre-headless \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
