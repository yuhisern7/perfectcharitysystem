FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY *.py .
COPY templates/ templates/

# Create directories for data and uploads
RUN mkdir -p data uploads

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "pcs-website:app", "--host", "0.0.0.0", "--port", "8000"]
