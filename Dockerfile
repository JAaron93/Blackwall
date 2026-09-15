FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create a non-root user
RUN addgroup --system --gid 1001 blackwall && \
    adduser --system --uid 1001 --gid 1001 blackwall

WORKDIR /app

# C toolchain required to link the maturin/PyO3 native extension
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definition files
COPY pyproject.toml README.md ./

# Copy Rust crate sources: maturin needs crates/<crate>/Cargo.toml at
# metadata-generation time, so the dependency layer cannot be built
# from pyproject.toml alone.
COPY crates/ ./crates/

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

# Smoke-check entrypoint: verifies the package imports cleanly as non-root.
# (A service entrypoint will replace this when the MCP Gateway CLI lands.)
CMD ["python", "-c", "import blackwall; print(blackwall.__version__)"]
