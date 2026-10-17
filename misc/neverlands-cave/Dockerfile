FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY index.html .

RUN adduser -D -u 10001 spotpod
USER 10001

EXPOSE 9090
CMD ["python", "app.py"]
