import threading
import socket
import json
import logging
import os
from datetime import datetime
from cryptography.fernet import Fernet
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class User:
    nickname: str
    client: socket.socket
    address: tuple
    is_admin: bool = False

class ChatServer:
    def __init__(self, host: str, port: int, max_clients: int = 50):
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users: Dict[str, User] = {}
        self.banned_users: List[str] = self._load_banned_users()
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
        
        logging.basicConfig(
            filename='server.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        
        self.upload_dir = "uploads"
        os.makedirs(self.upload_dir, exist_ok=True)

    def start(self):
        """Start the chat server"""
        try:
            self.server.bind((self.host, self.port))
            self.server.listen(self.max_clients)
            logging.info(f"Server started on {self.host}:{self.port}")
            print(f"Server is listening on {self.host}:{self.port}")
            self._accept_connections()
        except Exception as e:
            logging.error(f"Server startup failed: {e}")
            raise

    def _load_banned_users(self) -> List[str]:
        """Load banned users from file"""
        try:
            with open('bans.txt', 'r') as f:
                return [line.strip() for line in f.readlines()]
        except FileNotFoundError:
            return []

    def _accept_connections(self):
        """Accept incoming client connections"""
        while True:
            try:
                client, address = self.server.accept()
                thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client, address)
                )
                thread.start()
            except Exception as e:
                logging.error(f"Error accepting connection: {e}")

    def _handle_client_connection(self, client: socket.socket, address: tuple):
        try:
            
            client.send(self.key)
            
            
            client.send(self._encrypt("NICK"))
            nickname = self._decrypt(client.recv(1024))

            
            if nickname in self.banned_users:
                client.send(self._encrypt("BAN"))
                client.close()
                return

            
            if nickname == 'admin':
                client.send(self._encrypt("PASS"))
                password = self._decrypt(client.recv(1024))
                if not self._verify_admin(password):
                    client.send(self._encrypt("REFUSE"))
                    client.close()
                    return
                is_admin = True
                client.send(self._encrypt("SUCCESS"))
            else:
                is_admin = False

            
            user = User(nickname, client, address, is_admin)
            self.users[nickname] = user
            
            
            user_list = list(self.users.keys())
            client.send(self._encrypt(f"USERLIST:{','.join(user_list)}"))
            
            
            self._broadcast(f"{nickname} joined the chat", exclude=nickname)
            
            
            self._handle_client_messages(user)
            
        except Exception as e:
            logging.error(f"Error handling client connection: {e}")
            client.close()

    def _handle_client_messages(self, user: User):
        """Handle incoming messages from a client"""
        while True:
            try:
                message = self._decrypt(user.client.recv(1024))
                
                if not message:
                    break

                if message.startswith('/'):
                    self._handle_command(message, user)
                else:
                    self._broadcast(f"{user.nickname}: {message}")
                    
            except Exception as e:
                logging.error(f"Error handling message from {user.nickname}: {e}")
                break
                
        self._handle_client_disconnect(user)

    def _handle_command(self, message: str, user: User):
        """Handle special commands"""
        parts = message[1:].split(' ', 2)
        command = parts[0].lower()
        
        if command == 'whisper' and len(parts) >= 3:
            target = parts[1]
            content = parts[2]
            self._whisper(user.nickname, target, content)
            
        elif command == 'file' and len(parts) >= 2:
            self._handle_file_transfer(user, parts[1])
            
        elif user.is_admin:  # Make sure user is admin
            if command == 'kick' and len(parts) >= 2:
                target = parts[1].strip()
                if target in self.users and target != "admin":  # Prevent kicking admin
                    self._kick_user(target)
            elif command == 'ban' and len(parts) >= 2:
                target = parts[1].strip()
                if target in self.users and target != "admin":  # Prevent banning admin
                    self._ban_user(target)


    def _whisper(self, sender: str, target: str, content: str):
        """Send a private message to a specific user"""
        if target in self.users:
            message = f"[Whisper from {sender}]: {content}"
            self.users[target].client.send(self._encrypt(message))
            
            # Also send confirmation to sender
            if sender != target:
                self.users[sender].client.send(
                    self._encrypt(f"[Whisper to {target}]: {content}")
                )
        else:
            self.users[sender].client.send(
                self._encrypt(f"Error: User {target} not found")
            )

    def _handle_file_transfer(self, sender: User, filename: str):
        """Handle file transfer from client"""
        try:
            
            size = int(self._decrypt(sender.client.recv(1024)))
            
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            save_name = f"{timestamp}_{filename}"
            path = os.path.join(self.upload_dir, save_name)
            
            
            with open(path, 'wb') as f:
                received = 0
                while received < size:
                    data = sender.client.recv(min(size - received, 8192))
                    if not data:
                        break
                    f.write(data)
                    received += len(data)

            
            self._broadcast(
                f"{sender.nickname} shared a file: {filename} "
                f"(Available as {save_name})"
            )
            
        except Exception as e:
            logging.error(f"File transfer error: {e}")
            sender.client.send(
                self._encrypt("Error occurred during file transfer")
            )

    def _broadcast(self, message: str, exclude: Optional[str] = None):
        """Broadcast message to all clients except excluded one"""
        encrypted = self._encrypt(message)
        for nickname, user in self.users.items():
            if nickname != exclude:
                try:
                    user.client.send(encrypted)
                except Exception as e:
                    logging.error(f"Error broadcasting to {nickname}: {e}")

    def _send_user_list(self):
        """Send updated user list to all clients"""
        user_list = list(self.users.keys())
        message = f"USERLIST:{','.join(user_list)}"
        self._broadcast(message)  # Send to all users

    def _handle_client_disconnect(self, user: User):
        """Handle client disconnection"""
        if user.nickname in self.users:
            del self.users[user.nickname]
            user.client.close()
            self._broadcast(f"{user.nickname} left the chat")
            self._send_user_list()  # Update user list after someone leaves
            logging.info(f"Client disconnected: {user.nickname}")

    def _encrypt(self, message: str) -> bytes:
        """Encrypt a message"""
        return self.cipher_suite.encrypt(message.encode())

    def _decrypt(self, message: bytes) -> str:
        """Decrypt a message"""
        return self.cipher_suite.decrypt(message).decode()

    def _verify_admin(self, password: str) -> bool:
        """Verify admin password"""
        
        return password == "adminpass"

    def _kick_user(self, nickname: str):
        """Kick a user from the server"""
        if nickname in self.users:
            user = self.users[nickname]
            try:
                
                user.client.send(self._encrypt("You have been kicked from the server"))
                
                self._broadcast(f"{nickname} has been kicked from the server")
                
                self._handle_client_disconnect(user)
            except Exception as e:
                logging.error(f"Error kicking user {nickname}: {e}")

    def _ban_user(self, nickname: str):
        """Ban a user from the server"""
        if nickname in self.users:
            try:
                
                if nickname not in self.banned_users:
                    self.banned_users.append(nickname)
                    with open('bans.txt', 'a') as f:
                        f.write(f"{nickname}\n")
                    
                
                self.users[nickname].client.send(self._encrypt("You have been banned from the server"))
                
                self._broadcast(f"{nickname} has been banned from the server")
                
                self._kick_user(nickname)
                
                logging.info(f"User banned: {nickname}")
            except Exception as e:
                logging.error(f"Error banning user {nickname}: {e}")
                
if __name__ == "__main__":
    server = ChatServer("0.0.0.0", 5500)
    server.start()
