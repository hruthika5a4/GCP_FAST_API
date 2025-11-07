# ---- Dockerfile ----
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy rest of the files
COPY . .

# Expose the port Cloud Run expects
ENV PORT=8080
EXPOSE 8080

# Start the FastAPI app with uvicorn
# Using 'exec' ensures proper signal handling and uses dynamic PORT
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
