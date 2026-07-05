FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create a non-root user
RUN addgroup --system --gid 1001 blackwall && \
    adduser --system --uid 1001 --gid 1001 blackwall

WORKDIR /app

# Copy dependency definition files
COPY pyproject.toml README.md ./

# Create a dummy structure to install dependencies first and leverage layer caching
RUN mkdir -p src/blackwall && touch src/blackwall/__init__.py
RUN pip install --no-cache-dir -e .


# Copy the rest of the application code
COPY src/ ./src/
COPY config/ ./config/

# Set appropriate permissions
RUN chown -R blackwall:blackwall /app

# Switch to non-root user
USER blackwall

# Command to run the application (placeholder, update when entrypoint is defined)
CMD ["python", "-m", "blackwall.main"]
