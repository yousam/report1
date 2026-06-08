FROM python:3.12-slim

ENV TZ=Asia/Shanghai
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY templates/ templates/

EXPOSE 5000

CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
