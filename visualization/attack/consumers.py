import json
import os
import warnings
from channels.generic.websocket import WebsocketConsumer
from py_attack                  import ATTACK

class AttackConsumer(WebsocketConsumer):

    def connect(self):
        """Accepts incoming connections."""
        self.accept()

    def disconnect(self, close_code):
        """Prints disconnected message."""
        print("Disconnected: {}".format(close_code))

    def receive(self, text_data):
        """Receive data"""
        # Interpret data as json
        data = json.loads(text_data)

        # Handle data
        if data.get('command') == 'load':
            # Load from path
            if 'path' in data:
                # Get path
                path = data.get('path')

                # In case path is file
                if os.path.isfile(path):
                    self.attack = ATTACK.load_pickle(path)
                # In case path is directory:
                else:
                    self.attack = ATTACK.load(path)

                # Send succes to
                self.send(text_data=json.dumps({
                    'action' : 'load-complete',
                    'success': True,
                }))

            elif 'url' in data:
                warnings.warn("Load from URL not implemented")
            else:
                warnings.warn(
                    "Unable to load, no 'path' or 'url' found: {}".format(data))

        else:
            # Print warning message
            warnings.warn("Unknown message received: {}".format(data))
