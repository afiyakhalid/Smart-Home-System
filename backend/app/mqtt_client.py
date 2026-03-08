import json
import threading
from typing import Callable, Optional
import paho.mqtt.client as mqtt
from .config import settings


class MQTTClient:
    def __init__(self):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._connected = threading.Event()
        self._on_event: Optional[Callable[[str, dict], None]] = None
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def set_event_handler(self, handler: Callable[[str, dict], None]):
        self._on_event = handler

    def connect(self):
        self.client.connect(settings.mqtt_host, settings.mqtt_port, keepalive=60)
        t = threading.Thread(target=self.client.loop_forever, daemon=True)
        t.start()
        self._connected.wait(timeout=5)

    def subscribe_events(self):
        self.client.subscribe("home/+/event")

    def publish_command(self, device_id: str, payload: dict):
        topic = f"home/{device_id}/cmd"
        self.client.publish(topic, json.dumps(payload), qos=1)

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        self._connected.set()

    def _on_message(self, client, userdata, msg):
        if not self._on_event:
            return
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            payload = {"raw": msg.payload.decode("utf-8", errors="ignore")}
        self._on_event(msg.topic, payload)