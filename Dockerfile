# Base Image: Lightweight Python 3.11
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Install system dependencies & requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and policy configurations
COPY app/ ./app/
COPY config/ ./config/

# Expose Gateway Port
EXPOSE 8080

# Run FastAPI engine via Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
