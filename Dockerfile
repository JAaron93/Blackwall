FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.2 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

ENV PATH="$POETRY_HOME/bin:$PATH"

# Create a non-root user
RUN addgroup --system --gid 1001 blackwall && \
    adduser --system --uid 1001 --gid 1001 blackwall

# Install Poetry
RUN apt-get update && apt-get install -y curl && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock README.md ./

# Install dependencies (no source code yet to leverage caching)
RUN poetry install --without dev --no-root

# Copy the rest of the application code
COPY src/ ./src/
COPY config/ ./config/

# Set appropriate permissions
RUN chown -R blackwall:blackwall /app

# Switch to non-root user
USER blackwall

# Command to run the application (placeholder, update when entrypoint is defined)
CMD ["poetry", "run", "python", "-m", "blackwall.main"]
