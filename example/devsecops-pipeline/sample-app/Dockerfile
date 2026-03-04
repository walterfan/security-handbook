# Sample Dockerfile with intentional issues for container scanning
# ⚠️ Contains deliberate misconfigurations for testing

FROM python:3.12-slim

# Issue: Running as root (no USER instruction)
WORKDIR /app

# Issue: Using ADD instead of COPY for local files
ADD requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ADD src/ ./src/

EXPOSE 5000

# Issue: No HEALTHCHECK

CMD ["python", "src/app.py"]
