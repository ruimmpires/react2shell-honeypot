FROM python:3.9-slim

WORKDIR /app

# FIX: Install both libraries
RUN pip install flask python-json-logger

COPY app.py .

# Create the log file (Make sure this matches the filename in your app.py!)
RUN touch /var/log/honeypot.json && chmod 666 /var/log/honeypot.json

# FIX: Document the correct port
EXPOSE 8080

# FIX: Prevent Python from trying to write .pyc files (Crashing read-only containers)
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "app.py"]
