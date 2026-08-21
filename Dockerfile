# Use an official, lightweight Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Create a non-privileged user and configure permissions
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/.backups && \
    touch /app/fortigate_agent.log && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set the default command to run when the container starts
ENTRYPOINT ["python", "main.py"]
CMD ["diagnose"]
