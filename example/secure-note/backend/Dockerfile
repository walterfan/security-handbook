FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Generate JWT keys if not present
RUN if [ ! -f certs/jwt_private.pem ]; then \
        mkdir -p certs && \
        openssl genrsa -out certs/jwt_private.pem 2048 && \
        openssl rsa -in certs/jwt_private.pem -pubout -out certs/jwt_public.pem; \
    fi

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
