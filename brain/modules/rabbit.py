import pika
import logging
import json
import time
from pika.exceptions import StreamLostError, AMQPConnectionError, ConnectionClosedByBroker


logger = logging.getLogger(__name__)


class Rabbit:


    def __init__(self, host, port, user, passwd, max_retries=5, retry_delay=2):
        logger.info(f"Connecting to rabbitmq: {host}:{port} ({user}:{passwd})")
        self.credentials = pika.PlainCredentials(user, passwd)
        self.parameters = pika.ConnectionParameters(
            host=host, 
            port=port, 
            credentials=self.credentials,
            # Disable AMQP heartbeats for compatibility with eventlet; rely on TCP keepalive
            heartbeat=0,
            blocked_connection_timeout=300,
            connection_attempts=3,
            retry_delay=1,
            socket_timeout=10
        )
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.connection = None
        self.channel = None
        self.declared_queues = []
        self._connect()

    def _connect(self):
        """Establish a connection to RabbitMQ with retries"""
        retry_count = 0
        while retry_count < self.max_retries:
            try:
                logger.info(f"Connecting to RabbitMQ (attempt {retry_count+1}/{self.max_retries})")
                self.connection = pika.BlockingConnection(self.parameters)
                self.channel = self.connection.channel()
                self.channel.basic_qos(prefetch_count=1)  # only fetch one task at a time
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

    def queue_declare(self, *args, **kwargs):
        """ wrapper to avoid declaring same queue multiple times (slow) """
        if kwargs["queue"] not in self.declared_queues:
            self.ensure_connection()
            self.channel.queue_declare(*args, **kwargs)
            self.declared_queues.append(kwargs["queue"])


    #### producer of task requests ####


    def send_treq(self, queue, reply_to, correlation_id, treq, retry_count=0):
        logger.info(f"Sending task request to {queue} (reply_to: {reply_to}, correlation_id: {correlation_id})")
        properties = pika.BasicProperties()
        properties.content_type = "application/json"
        properties.delivery_mode = pika.spec.PERSISTENT_DELIVERY_MODE
        properties.reply_to = reply_to
        properties.correlation_id = correlation_id
        
        try:
            if not self.ensure_connection():
                return {"success": False, "error": "Failed to establish connection", "data": None}
                
            self.queue_declare(queue=queue, durable=True)
            self.channel.basic_publish(
                exchange="",
                routing_key=queue,
                body=json.dumps(treq),
                properties=properties
            )
            logger.info(f"Successfully sent task request to {queue}")
            return {"success": True, "error": None, "data": None}
            
        except (StreamLostError, AMQPConnectionError, ConnectionClosedByBroker) as e:
            logger.error(f"Connection error while sending task request to {queue}: {e}")
            
            if retry_count >= self.max_retries:
                logger.error(f"Max retries ({self.max_retries}) reached when sending to {queue}")
                return {"success": False, "error": f"Failed after {self.max_retries} attempts: {str(e)}", "data": None}
                
            logger.info(f"Retrying in {self.retry_delay} seconds... (attempt {retry_count+1}/{self.max_retries})")
            time.sleep(self.retry_delay)
            
            # Try to reconnect before retrying
            try:
                self._connect()
            except Exception as conn_err:
                logger.error(f"Failed to reconnect: {conn_err}")
                
            return self.send_treq(queue, reply_to, correlation_id, treq, retry_count=retry_count+1)
            
        except Exception as e:
            logger.error(f"Failed to send task request to {queue}: {e}")
            return {"success": False, "error": str(e), "data": None}
