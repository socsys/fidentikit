FROM mcr.microsoft.com/playwright/python:v1.35.0-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    libxcursor1 \
    libxdamage1 \
    libxi6 \
    libxtst6 \
    libnss3 \
    libcups2 \
    libxss1 \
    libxrandr2 \
    libasound2 \
    libpangocairo-1.0-0 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libgbm1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install pipenv
ENV PIPENV_VENV_IN_PROJECT=1

RUN mkdir -p /app
WORKDIR /app

ADD Pipfile .
ADD Pipfile.lock .
RUN pipenv install --system

COPY . .

RUN chmod +x /app/start.sh 2>/dev/null || true

ENV DISPLAY=:99
