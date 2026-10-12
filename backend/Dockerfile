FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ghostforge ./ghostforge
EXPOSE 8088
CMD ["uvicorn", "ghostforge.main:app", "--host", "0.0.0.0", "--port", "8088"]
