FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY icap_server ./icap_server
USER 10001:10001
EXPOSE 1344
CMD ["python", "-m", "icap_server"]
