# PyChat: Interactive Socket Chat Application

A secure multi-threaded chat application built with Python, enabling real-time encrypted messaging and file transfer between multiple clients.

## Features

- Real-time messaging with multiple clients
- End-to-end encryption using Fernet
- Private messaging with `/whisper` command
- File transfer capabilities
- Admin authentication and management (kick/ban users)
- User-friendly Tkinter GUI
- Comprehensive logging system

## Prerequisites

- Python 3.8+
- cryptography library
- tkinter (usually comes with Python)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pychat.git
cd pychat

# Install dependencies
pip install cryptography
```

## Usage

1. Start the server:
```bash
python server.py
```

2. Launch the client:
```bash
python client.py
```

3. Enter your username and connect to the server

### Admin Commands
- `/kick <username>`: Kick a user from the chat
- `/ban <username>`: Ban a user from the chat
- `/whisper <username> <message>`: Send a private message

## Project Structure

```
pychat/
├── server.py          # Server implementation
├── client.py          # Client and GUI implementation
├── encryption.py      # Encryption utilities
└── logs/             # Server logs directory
```

## Security Features

- Message encryption using Fernet
- Secure file transfer
- Admin authentication
- Activity logging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Push to the branch
5. Open a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
