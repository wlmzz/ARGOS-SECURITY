FROM python:3.12-slim

WORKDIR /app
COPY server/requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt

COPY . .

EXPOSE 8443
CMD ["python", "-m", "server.server", "--host", "0.0.0.0", "--port", "8443"]
