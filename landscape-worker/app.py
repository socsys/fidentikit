import os
import time
import logging
import sys

sys.path.insert(0, '/app')
sys.path.insert(0, '/app/landscape-worker')

from modules.helper.rabbit import RabbitHelper

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", 5672))
RABBITMQ_TLS = os.environ.get("RABBITMQ_TLS", "0")
RABBITMQ_QUEUE = os.environ.get("RABBITMQ_QUEUE", "landscape_analysis")
BRAIN_URL = os.environ.get("BRAIN_URL", "http://brain:8080")
SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://searxng:8080")
TMP_PATH = os.environ.get("TMP_PATH", "/tmpfs")

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper()),
    format="%(asctime)s:%(name)s:%(levelname)s:%(message)s"
)

def main():
    rabbit = None
    while True:
        try:
            rabbit = RabbitHelper(
                ADMIN_USER, ADMIN_PASS,
                RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_TLS, RABBITMQ_QUEUE, BRAIN_URL
            )
            logger.info(f"Start consuming: {RABBITMQ_QUEUE}")
            rabbit.channel.start_consuming()
        except KeyboardInterrupt:
            logger.info(f"Stop consuming: {RABBITMQ_QUEUE}")
            rabbit.channel.stop_consuming()
            break
        except Exception as e:
            logger.error(f"Error consuming: {RABBITMQ_QUEUE}")
            logger.debug(e)
            time.sleep(30)
    if rabbit:
        rabbit.connection.close()

if __name__ == "__main__":
    main()
