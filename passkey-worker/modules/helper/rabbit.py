import pika
import logging
import json
import time
import threading
import multiprocessing
import ssl
import requests
from modules.analyzers import ANALYZER
from pika.exceptions import StreamLostError, AMQPConnectionError, ConnectionClosedByBroker


logger = logging.getLogger(__name__)


class RabbitHelper:


    def __init__(
        self, admin_user: str, admin_password: str,
        rabbit_host: str, rabbit_port: int, rabbit_tls: str, rabbit_queue: str, brain_url: str,
        max_retries=5, retry_delay=2
    ):
        logger.info(f"Connecting to rabbitmq: {admin_user}:{admin_password}@{rabbit_host}:{rabbit_port} (tls={rabbit_tls})")
        logger.info(f"Connecting to queue: {rabbit_queue}")
        logger.info(f"Connecting to brain: {admin_user}:{admin_password}@{brain_url}")

        # brain credentials
        self.brain_url = brain_url
        self.brain_user = admin_user
        self.brain_password = admin_password

        # connection settings
        self.rabbit_host = rabbit_host
        self.rabbit_port = rabbit_port
        self.rabbit_tls = rabbit_tls
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # rabbit credentials
        self.credentials = pika.PlainCredentials(admin_user, admin_password)
        
        # Setup parameters with improved connection settings
        self._setup_parameters()
        
        # rabbit queue
        self.queue = rabbit_queue
        self.analysis = rabbit_queue
        
        # Initialize connection
        self.connection = None
        self.channel = None
        self._connect()
        
    def _setup_parameters(self):
        """Set up connection parameters with resilience settings"""
        if self.rabbit_tls == "1": # tls
            ctx = ssl.SSLContext()
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_default_certs()
            self.parameters = pika.ConnectionParameters(
                host=self.rabbit_host, 
                port=self.rabbit_port, 
                credentials=self.credentials,
                ssl_options=pika.SSLOptions(ctx),
                # Use a longer heartbeat to reduce false positives
                heartbeat=120,
                blocked_connection_timeout=300,
                connection_attempts=3,
                retry_delay=1,
                socket_timeout=10
            )
        else: # no tls
            self.parameters = pika.ConnectionParameters(
                host=self.rabbit_host, 
                port=self.rabbit_port, 
                credentials=self.credentials,
                # Use a longer heartbeat to reduce false positives
                heartbeat=120,
                blocked_connection_timeout=300,
                connection_attempts=3,
                retry_delay=1,
                socket_timeout=10
            )

    def _connect(self):
        """Establish a connection to RabbitMQ with retries"""
        retry_count = 0
        while retry_count < self.max_retries:
            try:
                logger.info(f"Connecting to RabbitMQ (attempt {retry_count+1}/{self.max_retries})")
                self.connection = pika.BlockingConnection(self.parameters)
                self.channel = self.connection.channel()
                self.channel.basic_qos(prefetch_count=1) # only fetch one message at a time
                
                # Set up queue for consumption
                self.channel.queue_declare(queue=self.queue, durable=True)
                self.channel.basic_consume(queue=self.queue, on_message_callback=self.on_message_callback)
                logger.info("Successfully connected to RabbitMQ")
                return True
                
            except (StreamLostError, AMQPConnectionError, ConnectionClosedByBroker) as e:
                logger.warning(f"Failed to connect to RabbitMQ: {e}")
                retry_count += 1
                if retry_count < self.max_retries:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"Failed to connect to RabbitMQ after {self.max_retries} attempts")
                    raise
        return False

    def ensure_connection(self):
        """Ensure that the connection and channel are active"""
        if self.connection is None or not self.connection.is_open:
            return self._connect()
        return True


    def on_message_callback(self, channel, method, properties, body):
        logger.info(f"Received message on queue: {self.queue}")
        t = threading.Thread(target=self.analyzer_executor, args=(channel, method, properties, body))
        t.daemon = True
        t.start()


    def analyzer_executor(self, channel, method, properties, body):
        logger.info(f"Executing message on queue: {self.queue}")

        tres = json.loads(body)

        tres["task_config"]["task_state"] = "REQUEST_RECEIVED"
        tres["task_config"]["task_timestamp_request_received"] = time.time()

        pool = multiprocessing.Pool(processes=1)
        workers = pool.apply_async(self.analyzer_process, args=(self.analysis, tres["domain"], tres[f"{self.analysis}_config"]))

        try:
            tres[f"{self.analysis}_result"] = workers.get(timeout=60*60*3) # 3 hours
            logger.info(f"Process finished executing message on queue: {self.queue}")
        except multiprocessing.TimeoutError:
            logger.error(f"Process timeout executing message on queue: {self.queue}")
            tres[f"{self.analysis}_result"] = {"exception": "Process timeout"}
            pool.terminate()
        finally:
            pool.close()
            pool.join()

        tres["task_config"]["task_state"] = "RESPONSE_SENT"
        tres["task_config"]["task_timestamp_response_sent"] = time.time()

        self.connection.add_callback_threadsafe(lambda: self.reply_data_and_ack_msg(channel, method, properties, tres))


    @staticmethod
    def analyzer_process(analysis: str, domain: str, config: dict) -> dict:
        try:
            return ANALYZER[analysis](domain, config).start()
        except Exception as e:
            logger.error(f"Exception while executing analyzer process: {analysis}")
            logger.debug(e)
            return {"exception": f"{e}"}


    def reply_data_and_ack_msg(self, channel, method, properties, data):
        logger.info(f"Reply data and acknowledge message received on queue: {self.queue}")
        # Handle replies to brain
        if properties.reply_to:
            retry_count = 0
            max_reply_retries = 10
            while retry_count < max_reply_retries:
                success = self.reply_data(properties.reply_to, data)
                if success:
                    break
                else:
                    retry_count += 1
                    retry_delay = min(60, self.retry_delay * (2 ** retry_count))  # Exponential backoff
                    logger.warning(f"Failed to reply data, retrying in {retry_delay} seconds (attempt {retry_count}/{max_reply_retries})...")
                    time.sleep(retry_delay)
            
            if retry_count >= max_reply_retries:
                logger.error(f"Failed to reply data after {max_reply_retries} attempts")
        
        # Ensure connection is active before acknowledging
        try:
            if not self.ensure_connection():
                logger.error("Cannot acknowledge message - failed to reconnect to RabbitMQ")
                return
                
            logger.info(f"Acknowledge message received on queue: {self.queue}")
            channel.basic_ack(delivery_tag=method.delivery_tag)
            
        except (StreamLostError, AMQPConnectionError, ConnectionClosedByBroker) as e:
            logger.error(f"Connection error while acknowledging message: {e}")
            # Try to reconnect
            if self._connect():
                # Re-delivery will happen automatically on reconnect
                logger.info("Reconnected to RabbitMQ, message will be redelivered")
            else:
                logger.error("Failed to reconnect to RabbitMQ")
        except Exception as e:
            logger.error(f"Error acknowledging message: {e}")


    def reply_data(self, reply_to: str, data: dict) -> bool:
        logger.info(f"Reply data from message received on queue {self.queue} to: {reply_to}")
        try:
            r = requests.put(f"{self.brain_url}{reply_to}", json=data, auth=(self.brain_user, self.brain_password))
        except Exception as e:
            logger.warning(f"Exception while replying data to: {reply_to}")
            logger.debug(e)
            return False
        if r.status_code != 200:
            logger.warning(f"Invalid status code ({r.status_code}) while replying data to: {reply_to}")
            return False
        logger.info(f"Successfully replied data to: {reply_to}")
        return True
