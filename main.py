import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import queue
import threading
import socket
import base64
import hashlib
import platform
from cryptography.fernet import Fernet, InvalidToken

# Import platform-specific notification modules
if platform.system() == "Linux":
    try:
        import notify2
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
elif platform.system() == "Darwin":  # macOS
    try:
        import os
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
elif platform.system() == "Windows":
    try:
        from win10toast import ToastNotifier
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
else:
    HAS_NOTIFICATIONS = False

# --- Crypto Utilities ---

# A salt is used to make the key derivation process more secure.
# Both clients MUST use the exact same salt.
SALT = b'encrypted-irc-salt-v1'

def derive_key(password: str) -> bytes:
    """
    Derives a secure 32-byte (256-bit) encryption key from a user-provided password.

    Args:
        password: The shared secret password.

    Returns:
        A 32-byte, base64-encoded key suitable for Fernet (AES-256).
    """
    kdf = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA-256
        password.encode('utf-8'),  # Convert password to bytes
        SALT,
        100000,  # Number of iterations (higher is more secure)
        dklen=32   # Desired key length (32 bytes = 256 bits)
    )
    # Fernet keys must be base64-encoded
    return base64.urlsafe_b64encode(kdf)

def encrypt_message(message: str, key: bytes) -> str:
    """
    Encrypts a string message using the derived key.

    Args:
        message: The plaintext message to encrypt.
        key: The base64-encoded key from derive_key().

    Returns:
        A base64-encoded encrypted token, as a string.
    """
    f = Fernet(key)
    encrypted_token = f.encrypt(message.encode('utf-8'))
    return encrypted_token.decode('utf-8')

def decrypt_message(token: str, key: bytes) -> str | None:
    """
    Decrypts an encrypted token back into a string message.

    Args:
        token: The base64-encoded encrypted token.
        key: The base64-encoded key from derive_key().

    Returns:
        The decrypted plaintext message, or None if decryption fails
        (e.g., wrong key, corrupt message).
    """
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(token.encode('utf-8'))
        return decrypted_message.decode('utf-8')
    except (InvalidToken, TypeError, Exception):
        # Catch exceptions if the token is invalid, corrupt, or not
        # a valid base64 string.
        return None

# --- IRC Connection Handler ---

class IRCHandler(threading.Thread):
    """
    Handles the raw socket connection to the IRC server in a separate thread
    to avoid blocking the main GUI.
    """
    def __init__(self, server, port, nick, channel, gui_queue):
        super().__init__()
        self.server = server
        self.port = port
        self.nick = nick
        self.channel = channel
        self.gui_queue = gui_queue  # Queue to send received messages to the GUI

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        # Set a timeout so the recv call does not block indefinitely
        self.sock.settimeout(5)

    def run(self):
        """Main thread loop: connect, join, and listen for messages."""
        try:
            self.sock.connect((self.server, self.port))
            self.send_command(f"NICK {self.nick}")
            self.send_command(f"USER {self.nick} 0 * :{self.nick}")

            # We wait for the server to acknowledge us before joining
            while self.running:
                try:
                    # Blocking call with timeout
                    data = self.sock.recv(4096).decode('utf-8')
                except socket.timeout:
                    # If timeout occurs, simply continue the loop to check self.running state
                    continue

                if not data:
                    break

                for line in data.splitlines():
                    if "001" in line: # 001 is the "Welcome" numeric
                        self.gui_queue.put(('SYSTEM_MESSAGE', f"Successfully joined {self.channel} on {self.server}."))
                        self.send_command(f"JOIN {self.channel}")

                    if line.startswith("PING"):
                        self.handle_ping(line)
                    elif "PRIVMSG" in line:
                        self.handle_privmsg(line)
                    # Add raw server output for debugging/status (optional)
                    elif not line.startswith(":"):
                        self.gui_queue.put(('SYSTEM_MESSAGE', line))

        except Exception as e:
            # Report critical connection errors back to the GUI
            error_message = f"Failed to connect or connection lost: {e}"
            self.gui_queue.put(('SYSTEM_ERROR', error_message))
        finally:
            self.stop()

    def send_command(self, command):
        """Sends a raw command to the IRC server."""
        if self.running:
            try:
                self.sock.send(f"{command}\r\n".encode('utf-8'))
            except BrokenPipeError:
                self.stop()

    def send_privmsg(self, message):
        """Sends an encrypted message to the channel."""
        self.send_command(f"PRIVMSG {self.channel} :{message}")

    def handle_ping(self, line):
        """Responds to server PINGs to keep the connection alive."""
        server = line.split(":")[-1]
        self.send_command(f"PONG :{server}")

    def handle_privmsg(self, line):
        """Parses a PRIVMSG and puts the sender/message in the GUI queue."""
        try:
            # Format: :<sender>!<user>@<host> PRIVMSG <channel> :<message>
            sender = line.split("!")[0][1:]
            message_content = line.split(":", 2)[-1]

            # We only care about messages in our channel from other users
            if self.channel in line and sender != self.nick:
                self.gui_queue.put((sender, message_content))
        except Exception as e:
            print(f"Error parsing PRIVMSG: {e}")

    def stop(self):
        """Stops the connection thread."""
        self.running = False
        try:
            # Send QUIT command before closing socket, if possible
            if self.sock.fileno() != -1:
                self.sock.send(f"QUIT :Client disconnecting\r\n".encode('utf-8'))
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except Exception:
            pass # Socket might already be closed or shut down

# --- GUI Main Application ---

class EncryptedIRCClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted IRC Client")
        self.root.geometry("600x500")
        self.original_title = self.root.title() # Store original title for notification
        
        # Initialize notification system
        if HAS_NOTIFICATIONS:
            if platform.system() == "Linux":
                notify2.init("LibreSilent")
            elif platform.system() == "Windows":
                self.toaster = ToastNotifier()

        # --- Top Frame (Settings) ---
        self.settings_frame = tk.Frame(root, pady=5)
        self.settings_frame.pack(fill='x')

        tk.Label(self.settings_frame, text="Server:").pack(side=tk.LEFT, padx=5)
        self.server_entry = tk.Entry(self.settings_frame, width=15)
        self.server_entry.insert(0, "irc.libera.chat")
        self.server_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(self.settings_frame, width=5)
        self.port_entry.insert(0, "6667")
        self.port_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Nick:").pack(side=tk.LEFT, padx=5)
        self.nick_entry = tk.Entry(self.settings_frame, width=10)
        self.nick_entry.insert(0, "EncryptedUser")
        self.nick_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Channel:").pack(side=tk.LEFT, padx=5)
        self.channel_entry = tk.Entry(self.settings_frame, width=10)
        # Channel will be generated from encryption key
        self.channel_entry.insert(0, "")
        self.channel_entry.config(state='disabled')  # User can't modify the channel
        self.channel_entry.pack(side=tk.LEFT)

        # Custom Channel button
        self.custom_channel_button = tk.Button(self.settings_frame, text="Custom Channel", command=self.toggle_custom_channel)
        self.custom_channel_button.pack(side=tk.LEFT, padx=5)
        self.using_custom_channel = False

        # Encrypt Names toggle button
        self.encrypt_names_button = tk.Button(self.settings_frame, text="Encrypt Names", command=self.toggle_name_encryption)
        self.encrypt_names_button.pack(side=tk.LEFT, padx=5)
        self.encrypt_names = True  # Default to encrypting names
        self.encrypt_names_button.config(relief=tk.SUNKEN)  # Show as active by default

        # Connect/Disconnect button (will toggle command and text)
        self.connect_button = tk.Button(self.settings_frame, text="Connect", command=self.connect)
        self.connect_button.pack(side=tk.RIGHT, padx=5)

        # --- Middle Frame (Chat Window) ---
        self.chat_window = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD, bg="#f0f0f0", relief=tk.SUNKEN, borderwidth=1)
        self.chat_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Bottom Frame (Message Entry) ---
        self.bottom_frame = tk.Frame(root, pady=5)
        self.bottom_frame.pack(fill='x')

        self.message_entry = tk.Entry(self.bottom_frame, state='disabled') # Disabled until connected
        self.message_entry.pack(fill='x', expand=True, side=tk.LEFT, padx=5)
        self.message_entry.bind("<Return>", self.send_message_event)

        self.send_button = tk.Button(self.bottom_frame, text="Send", command=self.send_message_event)
        self.send_button.pack(side=tk.RIGHT, padx=5)

        # --- Class variables ---
        self.gui_queue = queue.Queue()
        self.irc_thread = None
        self.encryption_key = None
        self.channel = None
        self.nick = None
        self.is_ready_to_send = False

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.display_message_system("Welcome! Enter server details and press Connect.")
        self.display_message_system("You will be prompted for your shared secret key after connecting.")

    def connect(self):
        server = self.server_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Port must be an integer.")
            return

        self.nick = self.nick_entry.get()

        if not all([server, port, self.nick]):
            messagebox.showerror("Error", "All fields except channel are required.")
            return

        # Prompt for the shared secret key
        password = simpledialog.askstring("Secret Key", "Enter your shared secret password:", show='*')
        if not password:
            self.display_message_system("Connection cancelled. No key provided.")
            return

        self.encryption_key = derive_key(password)
        
        if self.using_custom_channel:
            self.channel = self.channel_entry.get()
            if not self.channel:
                messagebox.showerror("Error", "Custom channel name is required.")
                return
            if not self.channel.startswith('#'):
                self.channel = f"#{self.channel}"
        else:
            # Generate channel name from encryption key
            channel_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
            self.channel = f"#ls{channel_hash}"  # 'ls' prefix for 'libresilent'
            self.channel_entry.config(state='normal')
            self.channel_entry.delete(0, tk.END)
            self.channel_entry.insert(0, self.channel)
            self.channel_entry.config(state='disabled')
        
        self.display_message_system(f"Key derived. Using channel {self.channel}")
        self.display_message_system(f"Connecting to {server}...")

        # Disable settings
        self.server_entry.config(state='disabled')
        self.port_entry.config(state='disabled')
        self.nick_entry.config(state='disabled')
        self.channel_entry.config(state='disabled')
        self.connect_button.config(text="Connecting...", state='disabled')

        # Start IRC connection
        self.irc_thread = IRCHandler(server, port, self.nick, self.channel, self.gui_queue)
        self.irc_thread.start()

        # Start checking the queue for new messages
        self.root.after(100, self.check_queue)

    def disconnect(self):
        """Stops the IRC thread and gracefully resets the application."""
        if self.irc_thread:
            self.display_message_system("Sending QUIT command to server and disconnecting...")
            self.irc_thread.stop()
            self.irc_thread = None
        self._reset_ui()
        self.display_message_system("Disconnected.")

    def check_queue(self):
        """Check the queue for messages from the IRC thread."""
        while not self.gui_queue.empty():
            sender, message = self.gui_queue.get_nowait()
            self.handle_incoming(sender, message)

        # Check if the thread has died unexpectedly
        if self.irc_thread and not self.irc_thread.is_alive() and self.is_ready_to_send:
            self.gui_queue.put(('SYSTEM_ERROR', "Connection thread unexpectedly terminated."))

        self.root.after(100, self.check_queue) # Poll again after 100ms

    def handle_incoming(self, sender, message):
        """Decrypts and displays an incoming message, or handles system errors."""
        if sender == 'SYSTEM_ERROR':
            self.display_message_error(message)
            self._reset_ui()
            return
        elif sender == 'SYSTEM_MESSAGE':
            self.display_message_system(message)
            # Check for the successful join message to enable sending
            if "Successfully joined" in message:
                self.is_ready_to_send = True
                self.message_entry.config(state='normal')
                # Toggle button to Disconnect mode
                self.connect_button.config(text="Disconnect", bg="salmon", state='normal', command=self.disconnect)
            return

        # Try to decrypt the message
        decrypted = decrypt_message(message, self.encryption_key)
        
        # If name encryption is enabled, try to decrypt the sender name
        displayed_sender = sender
        if self.encrypt_names and sender != self.nick:
            try:
                # The sender name might be encrypted
                decrypted_sender = decrypt_message(sender, self.encryption_key)
                if decrypted_sender:
                    displayed_sender = decrypted_sender
            except Exception:
                # If decryption fails, use the original sender name
                pass

        if decrypted:
            display = f"<{displayed_sender}> {decrypted}"
            self.display_message(display)

            # Show system notification
            self.show_notification("New Message", f"Message from {displayed_sender}")

            # Change window title to alert user
            self.root.title(f"** NEW MESSAGE ** - {self.original_title}")

        else:
            # This could be a normal IRC message, a message from a non-encrypted
            # user, or a corrupt message.
            self.display_message_system(f"<{sender}> [Unencrypted or corrupt message]")

    def send_message_event(self, event=None):
        """Handles the 'Send' button click or Enter key press."""
        message = self.message_entry.get()

        # Restore title after sending a message (assuming user is now looking)
        if self.root.title().startswith("** NEW MESSAGE **"):
            self.root.title(self.original_title)

        # Check if connection is ready before attempting to send
        if message and self.irc_thread and self.encryption_key and self.is_ready_to_send:
            # Encrypt and send (encrypt_message is defined globally)
            encrypted_message = encrypt_message(message, self.encryption_key)
            self.irc_thread.send_privmsg(encrypted_message)

            # If name encryption is enabled, encrypt our nickname
            if self.encrypt_names:
                encrypted_nick = encrypt_message(self.nick, self.encryption_key)
                self.irc_thread.nick = encrypted_nick  # Update the IRC thread's nick
                
            # Display our own message in the chat window
            self.display_message(f"<{self.nick}> {message}")

            self.message_entry.delete(0, tk.END)
        elif message and not self.is_ready_to_send:
             self.display_message_system("Please wait for the channel join message before sending.")


    def display_message(self, message):
        """Inserts a message into the chat window."""
        self.chat_window.config(state='normal')
        self.chat_window.insert(tk.END, message + "\n")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END) # Auto-scroll to bottom

    def display_message_system(self, message):
        """Displays a system message in a different color."""
        self.chat_window.config(state='normal')
        # Create a tag for system messages (italic, gray)
        self.chat_window.tag_configure("system", foreground="gray", font=("Arial", 10, "italic"))
        self.chat_window.insert(tk.END, message + "\n", "system")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END)

    def display_message_error(self, message):
        """Displays a critical error message in a special format."""
        self.chat_window.config(state='normal')
        self.chat_window.tag_configure("error", foreground="red", font=("Arial", 10, "bold"))
        self.chat_window.insert(tk.END, "--- CRITICAL ERROR ---\n", "error")
        self.chat_window.insert(tk.END, message + "\n", "error")
        self.chat_window.insert(tk.END, "----------------------\n", "error")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END) # Auto-scroll to bottom

    def show_notification(self, title, message):
        """Shows a system notification."""
        if not HAS_NOTIFICATIONS:
            return
            
        try:
            if platform.system() == "Linux":
                notification = notify2.Notification(title, message)
                notification.show()
            elif platform.system() == "Darwin":
                os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
            elif platform.system() == "Windows":
                self.toaster.show_toast(title, message, duration=5, threaded=True)
        except Exception as e:
            print(f"Failed to show notification: {e}")

    def toggle_name_encryption(self):
        """Toggles the encryption of usernames."""
        self.encrypt_names = not self.encrypt_names
        if self.encrypt_names:
            self.encrypt_names_button.config(relief=tk.SUNKEN)
            self.display_message_system("Name encryption enabled")
        else:
            self.encrypt_names_button.config(relief=tk.RAISED)
            self.display_message_system("Name encryption disabled")

    def toggle_custom_channel(self):
        """Toggles between custom and auto-generated channel."""
        if self.using_custom_channel:
            self.channel_entry.config(state='disabled')
            self.custom_channel_button.config(relief=tk.RAISED)
            self.using_custom_channel = False
            self.channel_entry.delete(0, tk.END)
        else:
            self.channel_entry.config(state='normal')
            self.custom_channel_button.config(relief=tk.SUNKEN)
            self.using_custom_channel = True

    def _reset_ui(self):
        """Resets all UI elements and state variables after disconnection or error."""
        self.server_entry.config(state='normal')
        self.port_entry.config(state='normal')
        self.nick_entry.config(state='normal')
        if not self.using_custom_channel:
            self.channel_entry.config(state='disabled')

        # Reset connect button state and color, set command back to connect
        # Using a fixed light gray to avoid platform-specific TclError
        self.connect_button.config(text="Connect", state='normal', bg='#E0E0E0', command=self.connect)

        self.irc_thread = None
        self.encryption_key = None
        self.is_ready_to_send = False
        self.message_entry.config(state='disabled')
        self.root.title(self.original_title) # Restore original title

    def on_closing(self):
        """Stops the IRC thread and closes the application."""
        if self.irc_thread:
            self.irc_thread.stop()
        self.root.destroy()

# --- Main execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedIRCClient(root)
    root.mainloop()
