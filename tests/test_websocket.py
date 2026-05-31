import pytest

def test_websocket_predictions(client):
    with client.websocket_connect("/ws/predictions") as websocket:
        websocket.send_text("ping")
