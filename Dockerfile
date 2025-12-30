FROM python:3.12-slim

WORKDIR /app

# Copy repo structure
COPY . .

# Install app in dev mode (for CLI access)
RUN pip install -e .

# Default: run tests
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
