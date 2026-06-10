FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY marlowe/ marlowe/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["marlowe"]
