FROM python:3.11-slim as builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/sbom-forge /usr/local/bin/sbom-forge

USER 1000:1000
ENTRYPOINT ["sbom-forge"]
CMD ["scan", "/app"]
