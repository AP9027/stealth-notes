FROM python:3.12-alpine
WORKDIR /app
COPY main.py requirements.txt index.html ./
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 3000
CMD ["python", "main.py"]
