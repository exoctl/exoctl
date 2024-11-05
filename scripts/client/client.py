#!/usr/bin/python3

import asyncio
import websockets
import sys
import os
import signal

class WebSocketClient:
    def __init__(self, uri, file_path):
        self.uri = uri
        self.file_path = file_path
        self.running = True
        self.websocket = None

    async def send_file(self):
        """Sends an entire file over the WebSocket."""
        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
                await self.websocket.send(file_data)
            print("File sent successfully.")
        except Exception as e:
            print(f"Error sending file: {e}")

    async def receive_messages(self):
        """Receives messages from the server."""
        while self.running:
            try:
                response = await self.websocket.recv()
                print(f"Received: {response}")
            except websockets.ConnectionClosed:
                break

    async def connect(self):
        """Connects to the WebSocket server and manages sending and receiving messages."""
        try:
            async with websockets.connect(self.uri) as websocket:
                self.websocket = websocket
                print("Connection established.")
                
                # Send the file immediately
                await self.send_file()

                # Start receiving messages
                receive_task = asyncio.create_task(self.receive_messages())

                # Wait for the receive task to finish
                await receive_task

        except (websockets.ConnectionClosed, ConnectionResetError) as e:
            print(f"Connection lost: {e}. Trying to reconnect...")

    def stop(self, signum, frame):
        """Stop the client on signal."""
        print("\nStopping the client...")
        self.running = False
        if self.websocket:
            asyncio.create_task(self.websocket.close())  # Close the WebSocket connection

async def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <ws://server_url> <file_path>")
        sys.exit(1)

    uri = sys.argv[1]
    file_path = sys.argv[2]

    # Check if the file exists
    if not os.path.isfile(file_path):
        print("Error: The specified file does not exist.")
        sys.exit(1)

    client = WebSocketClient(uri, file_path)

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, client.stop)

    # Run the connection
    try:
        await client.connect()
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())

