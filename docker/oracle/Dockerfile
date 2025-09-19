FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir pycryptodome

COPY aes_local_server.py /app/aes_local_server.py

EXPOSE 4356

CMD ["python", "/app/aes_local_server.py"]
