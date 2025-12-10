#!/bin/bash
# Start script for V-Auth worker

# Wait for dependencies
echo "Waiting for RabbitMQ..."
while ! nc -z ${RABBITMQ_HOST:-rabbitmq} ${RABBITMQ_PORT:-5672}; do
  sleep 1
done
echo "RabbitMQ is ready!"

# Start the application
echo "Starting V-Auth worker..."
exec xvfb-run -a python app.py

