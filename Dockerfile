# Use an official Python runtime as a parent image
FROM python:3.9-slim-bookworm

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies including wkhtmltopdf with necessary dependencies for proper rendering
RUN apt-get update && apt-get install -y --no-install-recommends \
    wkhtmltopdf \
    xfonts-base \
    xfonts-75dpi \
    fontconfig \
    libfontconfig1 \
    libxrender1 \
    xvfb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add a wrapper script to use Xvfb for headless PDF generation
RUN echo '#!/bin/bash\nxvfb-run -a --server-args="-screen 0, 1024x768x24" /usr/bin/wkhtmltopdf "$@"' > /usr/local/bin/wkhtmltopdf.sh \
    && chmod +x /usr/local/bin/wkhtmltopdf.sh

# Set the working directory in the container
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Create directory for temp files if it doesn't exist
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads

# Create necessary directories for the application
RUN mkdir -p /app/config /app/scripts /app/tests

# Set environment variables
ENV UPLOAD_FOLDER=/tmp/uploads \
    PORT=5000 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PORT_CONFIG=/app/port_config.yaml

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run gunicorn for production
CMD gunicorn --bind 0.0.0.0:$PORT app:app