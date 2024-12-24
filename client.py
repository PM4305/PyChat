import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket
import threading
import json
import os
from cryptography.fernet import Fernet
from typing import Optional, Dict
from datetime import datetime

class ChatClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Client")
        
        
        self.client: Optional[socket.socket] = None
        self.cipher_suite: Optional[Fernet] = None
        self.nickname: str = ""
        self.is_admin: bool = False
        self.connected = False
        self.server_info: Dict = self.load_servers()
        self.setup_gui()
        # Start with the login frame
        self.show_login_frame()
        
    def setup_gui(self):
        """Initialize the GUI components"""
        # Set up the main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Create frames for different views
        self.login_frame = ttk.Frame(self.main_container)
        self.chat_frame = ttk.Frame(self.main_container)
        
        # Set up styles
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))
        style.configure('Status.TLabel', font=('Helvetica', 10))
        
        self.setup_login_frame()
        self.setup_chat_frame()
        
    def setup_login_frame(self):
        """Set up the login interface"""
        # Server selection
        ttk.Label(self.login_frame, text="Chat Login", style='Title.TLabel').pack(pady=10)
        
        server_frame = ttk.Frame(self.login_frame)
        server_frame.pack(fill='x', pady=5)
        
        ttk.Label(server_frame, text="Server:").pack(side='left')
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(server_frame, textvariable=self.server_var)
        self.server_combo['values'] = list(self.server_info.keys())
        self.server_combo.pack(side='left', padx=5)
        
        # Add server button
        ttk.Button(server_frame, text="Add Server", command=self.show_add_server_dialog).pack(side='left', padx=5)
        
        # Nickname entry
        nick_frame = ttk.Frame(self.login_frame)
        nick_frame.pack(fill='x', pady=5)
        ttk.Label(nick_frame, text="Nickname:").pack(side='left')
        self.nickname_entry = ttk.Entry(nick_frame)
        self.nickname_entry.pack(side='left', padx=5)
        self.nickname_entry.bind('<KeyRelease>', self._on_nickname_change)
        
        # Password entry (for admin)
        self.pass_frame = ttk.Frame(self.login_frame)
        ttk.Label(self.pass_frame, text="Password:").pack(side='left')
        self.password_entry = ttk.Entry(self.pass_frame, show="*")
        self.password_entry.pack(side='left', padx=5)
        self.pass_frame.pack(fill='x', pady=5)
        
        # Connect button
        ttk.Button(self.login_frame, text="Connect", command=self.connect_to_server).pack(pady=10)
        
        # Status label
        self.login_status = ttk.Label(self.login_frame, text="", style='Status.TLabel')
        self.login_status.pack(pady=5)

    def _on_nickname_change(self, *args):
        nickname = self.nickname_entry.get().strip()
        if nickname == 'admin':
            self.pass_frame.pack(fill='x', pady=5)
        else:
            self.pass_frame.pack_forget()
            
    def setup_chat_frame(self):
        """Set up the main chat interface"""
        # Chat area with messages
        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, height=20)
        self.chat_area.pack(expand=True, fill='both', pady=5)
        self.chat_area.config(state='disabled')
        
        # Improve online users list
        users_frame = ttk.LabelFrame(self.chat_frame, text="Online Users")
        users_frame.pack(fill='both', expand=True, padx=5, pady=5)
    
        # Add scrollbar for users list
        users_scroll = ttk.Scrollbar(users_frame)
        users_scroll.pack(side='right', fill='y')
    
        self.users_list = tk.Listbox(users_frame, height=10, yscrollcommand=users_scroll.set)
        self.users_list.pack(fill='both', expand=True, padx=2, pady=2)
        users_scroll.config(command=self.users_list.yview)
        
        # Message input area
        input_frame = ttk.Frame(self.chat_frame)
        input_frame.pack(fill='x', pady=5)
        
        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side='left', fill='x', expand=True)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.chat_frame)
        buttons_frame.pack(fill='x')
        
        ttk.Button(buttons_frame, text="Send", command=self.send_message).pack(side='left', padx=2)
        ttk.Button(buttons_frame, text="Send File", command=self.send_file).pack(side='left', padx=2)
        ttk.Button(buttons_frame, text="Whisper", command=self.show_whisper_dialog).pack(side='left', padx=2)
        
        # Admin buttons (initially hidden)
        self.admin_frame = ttk.Frame(buttons_frame)
        ttk.Button(self.admin_frame, text="Kick", command=self.show_kick_dialog).pack(side='left', padx=2)
        ttk.Button(self.admin_frame, text="Ban", command=self.show_ban_dialog).pack(side='left', padx=2)
        
    def show_login_frame(self):
        """Show the login frame"""
        self.chat_frame.pack_forget()
        self.login_frame.pack(expand=True, fill='both')
        
    def show_chat_frame(self):
        """Show the chat frame"""
        self.login_frame.pack_forget()
        self.chat_frame.pack(expand=True, fill='both')
        
        if self.nickname == 'admin':
            self.admin_frame.pack(side='left', padx=5)

    def connect_to_server(self):
        try:
            server_name = self.server_var.get()
            if not server_name:
                self.show_error("Please select a server")
                return
                
            server_data = self.server_info[server_name]
            self.nickname = self.nickname_entry.get().strip()
            
            if not self.nickname:
                self.show_error("Please enter a nickname")
                return
                
            # Create socket and connect
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((server_data["ip"], server_data["port"]))
            
            # Receive encryption key
            self.cipher_suite = Fernet(self.client.recv(1024))
            
            # Handle initial server communication
            response = self._decrypt(self.client.recv(1024))
            
            if response == "NICK":
                self._encrypt_send(self.nickname)
                
                if self.nickname == "admin":
                    response = self._decrypt(self.client.recv(1024))
                    
                    if response == "PASS":
                        password = self.password_entry.get()
                        self._encrypt_send(password)
                        response = self._decrypt(self.client.recv(1024))
                        
                        if response == "REFUSE":
                            self.show_error("Invalid admin password")
                            self.client.close()
                            return
                        elif response == "SUCCESS":  # Check specifically for SUCCESS
                            self.is_admin = True  # Set the admin flag
                        else:
                            self.show_error("Authentication failed")
                            self.client.close()
                            return
                
                elif response == "BAN":
                    self.show_error("You are banned from this server")
                    self.client.close()
                    return
                
            self.connected = True
            self.show_chat_frame()
            
            # Start receiving messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except Exception as e:
            self.show_error(f"Connection failed: {str(e)}")
            if self.client:
                self.client.close()
                
    def receive_messages(self):
        while self.connected:
            try:
                message = self._decrypt(self.client.recv(1024))
                
                if message.startswith("USERLIST:"):
                    users = message[9:].split(',')
                    self.update_users_list(users)
                elif message.startswith("FILE:"):
                    self.handle_incoming_file(message[5:])
                else:
                    self.display_message(message)
                    
            except Exception as e:
                if self.connected:
                    self.handle_disconnect(f"Connection error: {str(e)}")
                break


    def send_message(self):
        """Send a message to the server"""
        message = self.message_entry.get().strip()
        if message and self.connected:
            try:
                self._encrypt_send(message)
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                self.show_error(f"Failed to send message: {str(e)}")

    def send_file(self):
        """Handle file sending"""
        if not self.connected:
            return
            
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                file_size = os.path.getsize(file_path)
                file_name = os.path.basename(file_path)
                
                # Send file transfer command
                self._encrypt_send(f"/file {file_name}")
                self._encrypt_send(str(file_size))
                
                # Send file data
                with open(file_path, 'rb') as f:
                    while data := f.read(8192):
                        self.client.send(data)
                        
                self.display_message(f"File {file_name} sent successfully")
                
            except Exception as e:
                self.show_error(f"Failed to send file: {str(e)}")

    def handle_incoming_file(self, file_info):
        """Handle incoming file transfer"""
        try:
            file_name, file_size = file_info.split(':', 1)
            file_size = int(file_size)
            
            save_path = filedialog.asksaveasfilename(
                defaultextension=os.path.splitext(file_name)[1],
                initialfile=file_name
            )
            
            if save_path:
                with open(save_path, 'wb') as f:
                    received = 0
                    while received < file_size:
                        data = self.client.recv(min(file_size - received, 8192))
                        if not data:
                            break
                        f.write(data)
                        received += len(data)
                        
                self.display_message(f"File {file_name} received and saved")
                
        except Exception as e:
            self.show_error(f"Failed to receive file: {str(e)}")

    def show_whisper_dialog(self):
        """Show dialog for sending private messages"""
        if not self.users_list.curselection():
            self.show_error("Please select a user to whisper to")
            return
            
        target = self.users_list.get(self.users_list.curselection())
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Whisper to {target}")
        
        ttk.Label(dialog, text="Message:").pack(pady=5)
        message_entry = ttk.Entry(dialog, width=40)
        message_entry.pack(pady=5)
        
        def send_whisper():
            message = message_entry.get().strip()
            if message:
                self._encrypt_send(f"/whisper {target} {message}")
                dialog.destroy()
                
        ttk.Button(dialog, text="Send", command=send_whisper).pack(pady=5)
        dialog.transient(self.root)
        dialog.grab_set()

    def show_kick_dialog(self):
        """Show dialog for kicking users (admin only)"""
        if not self.is_admin:  # Use is_admin flag
            return
            
        if not self.users_list.curselection():
            self.show_error("Please select a user to kick")
            return
            
        target = self.users_list.get(self.users_list.curselection())
        if target == "admin":  # Prevent kicking admin
            self.show_error("Cannot kick admin")
            return
            
        if messagebox.askyesno("Confirm Kick", f"Are you sure you want to kick {target}?"):
            self._encrypt_send(f"/kick {target}")

    def show_ban_dialog(self):
        """Show dialog for banning users (admin only)"""
        if not self.is_admin:  # Use is_admin flag
            return
            
        if not self.users_list.curselection():
            self.show_error("Please select a user to ban")
            return
            
        target = self.users_list.get(self.users_list.curselection())
        if target == "admin":  # Prevent banning admin
            self.show_error("Cannot ban admin")
            return
            
        if messagebox.askyesno("Confirm Ban", f"Are you sure you want to ban {target}?"):
            self._encrypt_send(f"/ban {target}")

    def _encrypt_send(self, message: str):
        """Encrypt and send a message"""
        self.client.send(self.cipher_suite.encrypt(message.encode()))

    def _decrypt(self, message: bytes) -> str:
        """Decrypt a received message"""
        return self.cipher_suite.decrypt(message).decode()

    def display_message(self, message: str):
        """Display a message in the chat area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, f"[{timestamp}] {message}\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state='disabled')

    def update_users_list(self, users: list):
        """Update the list of online users"""
        self.users_list.delete(0, tk.END)
        for user in users:
            user = user.strip()
            if user:  # Only add non-empty usernames
                self.users_list.insert(tk.END, user)

    def load_servers(self) -> Dict:
        """Load server information from file"""
        try:
            with open('servers.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_servers(self):
        """Save server information to file"""
        with open('servers.json', 'w') as f:
            json.dump(self.server_info, f, indent=4)

    def show_add_server_dialog(self):
        """Show dialog for adding a new server"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Server")
        
        ttk.Label(dialog, text="Server Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog)
        name_entry.pack(pady=5)
        
        ttk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Port:").pack(pady=5)
        port_entry = ttk.Entry(dialog)
        port_entry.pack(pady=5)
        
        def add_server():
            name = name_entry.get().strip()
            ip = ip_entry.get().strip()
            try:
                port = int(port_entry.get().strip())
                if name and ip:
                    self.server_info[name] = {"ip": ip, "port": port}
                    self.save_servers()
                    self.server_combo['values'] = list(self.server_info.keys())
                    dialog.destroy()
                else:
                    self.show_error("Please fill all fields")
            except ValueError:
                self.show_error("Port must be a number")
                
        ttk.Button(dialog, text="Add", command=add_server).pack(pady=10)
        dialog.transient(self.root)
        dialog.grab_set()

    def show_error(self, message: str):
        """Show error message"""
        messagebox.showerror("Error", message)

    def handle_disconnect(self, error_message: str = None):
        """Handle disconnection from server"""
        self.connected = False
        if self.client:
            self.client.close()
        if error_message:
            self.show_error(error_message)
        self.show_login_frame()

    def run(self):
        """Start the chat client"""
        self.root.mainloop()

if __name__ == "__main__":
    client = ChatClient()
    client.run()        
