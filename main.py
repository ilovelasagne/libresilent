import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
import queue
import threading
import socket
import base64
import hashlib
import platform
import socks
import requests
import json
import os
import datetime
import argparse
import sys
from tkinter import ttk
from cryptography.fernet import Fernet, InvalidToken

                                        
if platform.system() == "Linux":
    try:
        import notify2
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
elif platform.system() == "Darwin":
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

                          
SALT = b'encrypted-irc-salt-v1'

                                                                   

class TerminalUIHandler:
    """handles terminal-based UI for IRC communication without GUI"""
    
    def __init__(self):
        self.running = True
        self.is_ready_to_send = False
        self.encryption_key = None
        self.irc_thread = None
        self.gui_queue = queue.Queue()
        self.input_thread = None
        self.nick = None
        self.channel = None
        self.use_tor = False
        self.tor_port = 9050
        self.encrypt_names = True
        self.use_rotation = False
        self.rotation_key = None
        
    def print_banner(self):
        """displays welcome banner"""
        print("\n" + "="*60)
        print("  LibreSilent - Encrypted IRC Client (Terminal Mode)")
        print("="*60)
        print("All messages are encrypted end-to-end")
        print("Type 'help' for commands, 'quit' to exit\n")
    
    def print_help(self):
        """displays available commands"""
        help_text = """
Available Commands:
  /help          - Show this help message
  /nick <name>   - Change nickname
  /channel       - Show current channel
  /info          - Show connection info
  /settings      - Show current settings
  /encrypt       - Toggle name encryption
  /rotation      - Toggle daily code rotation
  /tor           - Toggle TOR connection
  /quit          - Disconnect and exit
  /clear         - Clear screen

Just type your message and press Enter to send encrypted messages.
"""
        print(help_text)
    
    def get_server_config(self):
        """prompts user for server configuration"""
        print("\n--- Server Configuration ---")
        server = input("IRC Server [irc.libera.chat]: ").strip() or "irc.libera.chat"
        port_str = input("Port [6667]: ").strip() or "6667"
        
        try:
            port = int(port_str)
        except ValueError:
            print("Error: Port must be a number. Using default 6667.")
            port = 6667
        
        nick = input("Nickname [EncryptedUser]: ").strip() or "EncryptedUser"
        
        return server, port, nick
    
    def get_encryption_settings(self):
        """prompts user for encryption settings"""
        print("\n--- Encryption Settings ---")
        
        password = input("Enter shared encryption key (password): ")
        while not password:
            print("Error: Encryption key cannot be empty.")
            password = input("Enter shared encryption key (password): ")
        
        use_rotation = input("Enable daily code rotation? (y/n) [n]: ").strip().lower() == 'y'
        rotation_key = None
        
        if use_rotation:
            rotation_key = input("Enter rotation key: ")
            while not rotation_key:
                print("Error: Rotation key cannot be empty.")
                rotation_key = input("Enter rotation key: ")
        
        return password, use_rotation, rotation_key
    
    def get_channel_choice(self):
        """prompts user to choose between auto and custom channel"""
        print("\n--- Channel Selection ---")
        choice = input("Use auto-generated channel? (y/n) [y]: ").strip().lower()
        
        if choice == 'n':
            custom_channel = input("Enter custom channel name: ").strip()
            if not custom_channel.startswith('#'):
                custom_channel = f"#{custom_channel}"
            return custom_channel
        else:
            return None
    
    def connect(self):
        """main connection flow"""
        self.print_banner()
        
        server, port, nick = self.get_server_config()
        self.nick = nick
        
        password, use_rotation, rotation_key = self.get_encryption_settings()
        self.use_rotation = use_rotation
        self.rotation_key = rotation_key
        
        custom_channel = self.get_channel_choice()
        
        if custom_channel:
            self.channel = custom_channel
        else:
            self.encryption_key = derive_key(password, rotation_key, use_rotation)
            channel_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
            self.channel = f"#ls{channel_hash}"
        
        self.encryption_key = derive_key(password, rotation_key, use_rotation)
        
        print(f"\nConnecting to {server}:{port} as {nick}...")
        print(f"Using channel: {self.channel}")
        
        self.irc_thread = IRCHandler(server, port, nick, self.channel, self.gui_queue, 
                                    use_tor=self.use_tor, tor_port=self.tor_port)
        self.irc_thread.start()
        
        print("Connected! Type your messages below. Type '/help' for commands.\n")
        print("-" * 60)
        
        self.input_thread = threading.Thread(target=self.input_loop, daemon=True)
        self.input_thread.start()
        
        self.message_loop()
    
    def input_loop(self):
        """handles user input in a separate thread"""
        while self.running:
            try:
                user_input = input()
                if user_input:
                    self.gui_queue.put(('USER_INPUT', user_input))
            except EOFError:
                self.gui_queue.put(('USER_INPUT', '/quit'))
                break
    
    def message_loop(self):
        """main message processing loop"""
        self.is_ready_to_send = False
        
        while self.running and self.irc_thread.is_alive():
            try:
                sender, message = self.gui_queue.get(timeout=0.5)
                
                if sender == 'USER_INPUT':
                    self.handle_user_input(message)
                elif sender == 'SYSTEM_MESSAGE':
                    if "Successfully joined" in message:
                        self.is_ready_to_send = True
                        print("[SYSTEM] Ready to send messages!")
                    print(f"[SYSTEM] {message}")
                elif sender == 'SYSTEM_ERROR':
                    print(f"[ERROR] {message}")
                    self.running = False
                else:
                    decrypted = decrypt_message(message, self.encryption_key)
                    
                    displayed_sender = sender
                    if self.encrypt_names and sender != self.nick:
                        try:
                            decrypted_sender = decrypt_message(sender, self.encryption_key)
                            if decrypted_sender:
                                displayed_sender = decrypted_sender
                        except Exception:
                            pass
                    
                    if decrypted:
                        print(f"<{displayed_sender}> {decrypted}")
                    else:
                        print(f"<{sender}> [Unencrypted or corrupt message]")
                    
                    print("> ", end="", flush=True)
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[ERROR] {e}")
                self.running = False
    
    def handle_user_input(self, user_input):
        """handles user commands and messages"""
        if user_input.startswith('/'):
            self.handle_command(user_input)
        elif self.is_ready_to_send and self.irc_thread and self.encryption_key:
            encrypted_message = encrypt_message(user_input, self.encryption_key)
            self.irc_thread.send_privmsg(encrypted_message)
            
            if self.encrypt_names:
                encrypted_nick = encrypt_message(self.nick, self.encryption_key)
                self.irc_thread.nick = encrypted_nick
            
            print(f"<{self.nick}> {user_input}")
            print("> ", end="", flush=True)
        elif user_input:
            print("[SYSTEM] Waiting for channel connection. Please wait...")
            print("> ", end="", flush=True)
    
    def handle_command(self, command):
        """handles slash commands"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        
        if cmd == '/help':
            self.print_help()
        elif cmd == '/quit':
            self.quit_app()
        elif cmd == '/nick':
            if len(parts) > 1:
                self.nick = parts[1]
                print(f"[SYSTEM] Nickname set to: {self.nick}")
            else:
                print(f"[SYSTEM] Current nickname: {self.nick}")
        elif cmd == '/channel':
            print(f"[SYSTEM] Current channel: {self.channel}")
        elif cmd == '/info':
            self.show_info()
        elif cmd == '/settings':
            self.show_settings()
        elif cmd == '/encrypt':
            self.encrypt_names = not self.encrypt_names
            status = "enabled" if self.encrypt_names else "disabled"
            print(f"[SYSTEM] Name encryption {status}")
        elif cmd == '/rotation':
            self.use_rotation = not self.use_rotation
            status = "enabled" if self.use_rotation else "disabled"
            print(f"[SYSTEM] Code rotation {status}")
        elif cmd == '/tor':
            if not self.use_tor:
                if self.check_tor_connection():
                    self.use_tor = True
                    print("[SYSTEM] TOR routing enabled")
                else:
                    print("[ERROR] Could not connect to TOR. Make sure it's running on port 9050.")
            else:
                self.use_tor = False
                print("[SYSTEM] TOR routing disabled")
        elif cmd == '/clear':
            os.system('clear' if platform.system() != 'Windows' else 'cls')
            self.print_banner()
        else:
            print(f"[SYSTEM] Unknown command: {cmd}. Type '/help' for available commands.")
        
        print("> ", end="", flush=True)
    
    def show_info(self):
        """displays connection information"""
        info = f"""
--- Connection Info ---
Channel: {self.channel}
Nickname: {self.nick}
Connected: {self.is_ready_to_send}
Name Encryption: {self.encrypt_names}
Code Rotation: {self.use_rotation}
TOR Enabled: {self.use_tor}
"""
        print(info)
    
    def show_settings(self):
        """displays current settings"""
        settings = f"""
--- Current Settings ---
Channel: {self.channel}
Nickname: {self.nick}
Name Encryption: {'Yes' if self.encrypt_names else 'No'}
Code Rotation: {'Yes' if self.use_rotation else 'No'}
TOR Routing: {'Yes' if self.use_tor else 'No'}
TOR Port: {self.tor_port if self.use_tor else 'N/A'}
"""
        print(settings)
    
    def check_tor_connection(self):
        """checks if tor is running and accessible"""
        try:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            sock.settimeout(5)
            sock.connect(("check.torproject.org", 443))
            sock.close()
            return True
        except Exception:
            return False
    
    def quit_app(self):
        """stops irc thread and exits application"""
        print("\n[SYSTEM] Disconnecting...")
        self.running = False
        if self.irc_thread:
            self.irc_thread.stop()
        print("[SYSTEM] Goodbye!")
        sys.exit(0)

                          

class ThemeManager:
    """handles application theming and system theme synchronization"""
    
                         
    LIGHT_THEME = {
        'bg': '#ffffff',
        'fg': '#000000',
        'frame_bg': '#f0f0f0',
        'entry_bg': '#ffffff',
        'entry_fg': '#000000',
        'text_bg': '#f0f0f0',
        'text_fg': '#000000',
        'button_bg': '#e0e0e0',
        'button_fg': '#000000',
        'system_fg': '#666666',
        'error_fg': '#cc0000',
    }
    
    DARK_THEME = {
        'bg': '#1e1e1e',
        'fg': '#ffffff',
        'frame_bg': '#2d2d2d',
        'entry_bg': '#2b2b2b',
        'entry_fg': '#ffffff',
        'text_bg': '#222222',
        'text_fg': '#ffffff',
        'button_bg': '#2b2b2b',
        'button_fg': '#ffffff',
        'system_fg': '#cccccc',
        'error_fg': '#ff6b6b',
    }
    
    CONFIG_DIR = os.path.expanduser('~/.config/libresilent')
    THEME_CONFIG_FILE = os.path.join(CONFIG_DIR, 'theme.json')
    
    @staticmethod
    def detect_system_theme() -> str:
        """detect system theme preference"""
        try:
            if platform.system() == "Linux":
                                                 
                result = os.popen('gsettings get org.gnome.desktop.interface gtk-application-prefer-dark-theme 2>/dev/null').read().strip()
                return 'dark' if 'true' in result else 'light'
            elif platform.system() == "Darwin":
                                        
                result = os.popen('defaults read -g AppleInterfaceStyle 2>/dev/null').read().strip()
                return 'dark' if 'Dark' in result else 'light'
            elif platform.system() == "Windows":
                                                      
                try:
                    import winreg
                    registry_path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
                    registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path)
                    value, regtype = winreg.QueryValueEx(registry_key, "AppsUseLightTheme")
                    return 'light' if value == 1 else 'dark'
                except:
                    return 'light'
        except:
            pass
        return 'light'
    
    @staticmethod
    def load_theme_preference() -> str:
        """load saved theme preference or auto-detect"""
        try:
            if os.path.exists(ThemeManager.THEME_CONFIG_FILE):
                with open(ThemeManager.THEME_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    if config.get('theme') in ['light', 'dark']:
                        return config['theme']
                    if config.get('auto_sync'):
                        return ThemeManager.detect_system_theme()
        except:
            pass
        return ThemeManager.detect_system_theme()
    
    @staticmethod
    def save_theme_preference(theme: str, auto_sync: bool = True):
        """save theme preference"""
        try:
            os.makedirs(ThemeManager.CONFIG_DIR, exist_ok=True)
            config = {
                'theme': theme,
                'auto_sync': auto_sync,
                'timestamp': datetime.datetime.now().isoformat()
            }
            with open(ThemeManager.THEME_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"failed to save theme preference: {e}")
    
    @staticmethod
    def get_theme_colors(theme: str) -> dict:
        """get color scheme for theme"""
        return ThemeManager.DARK_THEME if theme == 'dark' else ThemeManager.LIGHT_THEME

                          

def get_daily_rotation(rotation_key: str) -> str:
    """generates daily rotation string based on rotation key and current date"""
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    daily_seed = f"{rotation_key}{current_date}"
    return hashlib.sha256(daily_seed.encode()).hexdigest()[:16]

def derive_key(password: str, rotation_key: str = None, use_rotation: bool = False) -> bytes:
    """derives 256-bit encryption key from password using PBKDF2-HMAC-SHA256"""
    if use_rotation and rotation_key:
        daily_rotation = get_daily_rotation(rotation_key)
        password = f"{password}{daily_rotation}"
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        SALT,
        100000,
        dklen=32
    )
    return base64.urlsafe_b64encode(kdf)

def encrypt_message(message: str, key: bytes) -> str:
    """encrypts message using Fernet (AES-256-CBC)"""
    f = Fernet(key)
    encrypted_token = f.encrypt(message.encode('utf-8'))
    return encrypted_token.decode('utf-8')

def decrypt_message(token: str, key: bytes) -> str | None:
    """decrypts message token, returns None on failure"""
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(token.encode('utf-8'))
        return decrypted_message.decode('utf-8')
    except (InvalidToken, TypeError, Exception):
        return None

                             

class SettingsManager:
    """handles encryption and persistence of application settings"""
    
    CONFIG_DIR = os.path.expanduser('~/.config/libresilent')
    DEFAULT_SETTINGS_FILE = os.path.join(CONFIG_DIR, 'settings.json')
    
    @staticmethod
    def ensure_config_dir():
        """ensures config directory exists"""
        os.makedirs(SettingsManager.CONFIG_DIR, exist_ok=True)
    
    @staticmethod
    def create_settings_dict(server: str, port: int, nick: str, channel: str, 
                            password: str, rotation_key: str = None, 
                            use_rotation: bool = False, use_tor: bool = False,
                            encrypt_names: bool = True, theme: str = 'auto') -> dict:
        """creates settings dictionary with configuration parameters"""
        return {
            'server': server,
            'port': port,
            'nick': nick,
            'channel': channel,
            'rotation_key': rotation_key,
            'use_rotation': use_rotation,
            'use_tor': use_tor,
            'encrypt_names': encrypt_names,
            'theme': theme,
            'created_date': datetime.datetime.now().isoformat(),
            'rotation_start_date': datetime.datetime.now().strftime("%Y%m%d") if use_rotation else None,
        }
    
    @staticmethod
    def save_settings(settings_dict: dict, password: str, filepath: str = None) -> bool:
        """encrypts and saves settings to file"""
        try:
            SettingsManager.ensure_config_dir()
            
            encryption_key = derive_key(password)
            
            settings_json = json.dumps(settings_dict, indent=2)
            
            encrypted_settings = encrypt_message(settings_json, encryption_key)
            
            wrapper = {
                'version': '1.0',
                'encrypted_data': encrypted_settings,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            target_file = filepath or SettingsManager.DEFAULT_SETTINGS_FILE
            with open(target_file, 'w') as f:
                json.dump(wrapper, f, indent=2)
            
            return True
        except Exception as e:
            print(f"error saving settings: {e}")
            return False
    
    @staticmethod
    def load_settings(password: str, filepath: str = None) -> dict | None:
        """loads and decrypts settings from file"""
        try:
            target_file = filepath or SettingsManager.DEFAULT_SETTINGS_FILE
            
            if not os.path.exists(target_file):
                return None
            
            with open(target_file, 'r') as f:
                wrapper = json.load(f)
            
            encrypted_settings = wrapper.get('encrypted_data')
            if not encrypted_settings:
                return None
            
            decryption_key = derive_key(password)
            
            decrypted_json = decrypt_message(encrypted_settings, decryption_key)
            if not decrypted_json:
                return None
            
            settings_dict = json.loads(decrypted_json)
            return settings_dict
        except Exception as e:
            print(f"error loading settings: {e}")
            return None
    
    @staticmethod
    def export_settings(settings_dict: dict, password: str, export_path: str) -> bool:
        """exports encrypted settings to file"""
        return SettingsManager.save_settings(settings_dict, password, export_path)
    
    @staticmethod
    def import_settings(password: str, import_path: str) -> dict | None:
        """imports encrypted settings from file"""
        return SettingsManager.load_settings(password, import_path)

                                

class IRCHandler(threading.Thread):
    """
    Handles the raw socket connection to the IRC server in a separate thread
    to avoid blocking the main GUI.
    """
    def __init__(self, server, port, nick, channel, gui_queue, use_tor=False, tor_port=9050):
        super().__init__()
        self.server = server
        self.port = port
        self.nick = nick
        self.channel = channel
        self.gui_queue = gui_queue                                              
        self.use_tor = use_tor
        self.tor_port = tor_port

        if self.use_tor:
            self.sock = socks.socksocket()
            self.sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        self.running = True
                                                                    
        self.sock.settimeout(5)

    def run(self):
        """Main thread loop: connect, join, and listen for messages."""
        try:
            self.sock.connect((self.server, self.port))
            self.send_command(f"NICK {self.nick}")
            self.send_command(f"USER {self.nick} 0 * :{self.nick}")

                                                                     
            while self.running:
                try:
                                                
                    data = self.sock.recv(4096).decode('utf-8')
                except socket.timeout:
                                                                                             
                    continue

                if not data:
                    break

                for line in data.splitlines():
                    if "001" in line:                               
                        self.gui_queue.put(('SYSTEM_MESSAGE', f"Successfully joined {self.channel} on {self.server}."))
                        self.send_command(f"JOIN {self.channel}")

                    if line.startswith("PING"):
                        self.handle_ping(line)
                    elif "PRIVMSG" in line:
                        self.handle_privmsg(line)
                                                                           
                    elif not line.startswith(":"):
                        self.gui_queue.put(('SYSTEM_MESSAGE', line))

        except Exception as e:
                                                               
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
                                                                          
            sender = line.split("!")[0][1:]
            message_content = line.split(":", 2)[-1]

                                                                         
            if self.channel in line and sender != self.nick:
                self.gui_queue.put((sender, message_content))
        except Exception as e:
            print(f"Error parsing PRIVMSG: {e}")

    def stop(self):
        """Stops the connection thread."""
        self.running = False
        try:
                                                                  
            if self.sock.fileno() != -1:
                self.sock.send(f"QUIT :Client disconnecting\r\n".encode('utf-8'))
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except Exception:
            pass                                              

                              

class EncryptedIRCClient:
    def apply_theme(self, theme: str):
        """applies theme to application"""
        self.colors = ThemeManager.get_theme_colors(theme)
        self.root.config(bg=self.colors['bg'])
                                                                        
        try:
            style = ttk.Style()
                                                                     
                                                                                 
            style.configure('TFrame', background=self.colors['frame_bg'])
            style.configure('TLabel', background=self.colors['frame_bg'], foreground=self.colors['fg'])
            style.configure('TButton', background=self.colors['button_bg'], foreground=self.colors['button_fg'])
            style.configure('TEntry', fieldbackground=self.colors['entry_bg'], foreground=self.colors['entry_fg'])
            style.configure('TCheckbutton', background=self.colors['frame_bg'], foreground=self.colors['fg'])
        except Exception:
            pass

                                                                                  
                                                                                                 
        try:
            if hasattr(self, 'settings_frame'):
                self.settings_frame.config(bg=self.colors['frame_bg'])
            if hasattr(self, 'bottom_frame'):
                self.bottom_frame.config(bg=self.colors['frame_bg'])
            if hasattr(self, 'chat_window'):
                                                                                
                self.chat_window.config(bg=self.colors['text_bg'], fg=self.colors['text_fg'], insertbackground=self.colors['text_fg'])
                                 
            for name in ('message_entry','server_entry','port_entry','nick_entry','channel_entry'):
                if hasattr(self, name):
                    w = getattr(self, name)
                    try:
                        w.config(bg=self.colors['entry_bg'], fg=self.colors['entry_fg'], insertbackground=self.colors['entry_fg'])
                    except Exception:
                        pass
            for name in ('custom_channel_button','encrypt_names_button','tor_button','rotation_button','connect_button','send_button'):
                if hasattr(self, name):
                    w = getattr(self, name)
                    try:
                        w.config(bg=self.colors['button_bg'], fg=self.colors['button_fg'], activebackground=self.colors['entry_bg'])
                    except Exception:
                        pass
        except Exception:
            pass
    
    def get_frame_style(self) -> dict:
        """returns frame styling kwargs"""
        return {
            'bg': self.colors['frame_bg']
        }
    
    def get_label_style(self) -> dict:
        """returns label styling kwargs"""
        return {
            'bg': self.colors['frame_bg'],
            'fg': self.colors['fg']
        }
    
    def get_entry_style(self) -> dict:
        """returns entry styling kwargs"""
        return {
            'bg': self.colors['entry_bg'],
            'fg': self.colors['entry_fg'],
            'insertbackground': self.colors['entry_fg']
        }
    
    def get_button_style(self) -> dict:
        """returns button styling kwargs"""
        return {
            'bg': self.colors['button_bg'],
            'fg': self.colors['button_fg'],
            'activebackground': self.colors['entry_bg'],
            'activeforeground': self.colors['button_fg']
        }
    
    def get_text_style(self) -> dict:
        """returns text widget styling kwargs"""
        return {
            'bg': self.colors['text_bg'],
            'fg': self.colors['text_fg'],
            'insertbackground': self.colors['text_fg']
        }
    
    def show_welcome_dialog(self):
        """displays welcome dialog with app instructions"""
        config_path = os.path.expanduser('~/.config/libresilent/config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                if config.get('skip_welcome', False):
                    return

        dialog = tk.Toplevel(self.root)
        dialog.title("Welcome to LibreSilent")
        dialog.geometry("600x500")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.config(bg=self.colors['bg'])

                      
        welcome_text = """Welcome to LibreSilent - Secure IRC Communication

HOW TO USE:
1. Basic Setup:
   • Enter a server (default: irc.libera.chat)
   • Choose a nickname
   • Share your encryption key with your intended contact
   
2. Security Features:
   • Name Encryption: Toggle to encrypt usernames (on by default)
   • Custom Channel: Create your own channel or use auto-generated
   • TOR Routing: Optional anonymous routing through TOR network
   
3. Connecting:
   • Click 'Connect' and enter your shared encryption key
   • Both users must use the same encryption key to communicate
   • The channel will be automatically generated from your key
   
4. Privacy Features:
   • All messages are encrypted end-to-end
   • Notifications appear for new messages
   • System tray alerts keep you informed
   
IMPORTANT:
• Keep your encryption key secure and private
• Both users must use identical encryption keys
• TOR requires separate installation if needed
• Custom channels are less secure than auto-generated ones

For maximum security:
1. Use auto-generated channels
2. Keep name encryption enabled
3. Use unique, strong encryption keys
4. Consider using TOR for additional anonymity"""

        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=20, **self.get_text_style())
        text_widget.pack(pady=10)
        text_widget.insert(tk.END, welcome_text)
        text_widget.config(state='disabled')

        var = tk.BooleanVar()
        check = ttk.Checkbutton(frame, text="Don't show this message again", variable=var)
        check.pack(pady=5)

        def on_close():
            if var.get():
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w') as f:
                    json.dump({'skip_welcome': True}, f)
            dialog.destroy()

        close_button = ttk.Button(frame, text="Got it!", command=on_close)
        close_button.pack(pady=10)

        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f'{width}x{height}+{x}+{y}')

    def create_menu_bar(self):
        """creates menu bar with File, Edit, View, and Help menus"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

                   
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New", command=self.menu_new)
        file_menu.add_command(label="Open", command=self.menu_open)
        file_menu.add_command(label="Save", command=self.menu_save)
        file_menu.add_command(label="Save As", command=self.menu_save_as)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)

                   
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Undo", command=self.menu_undo)
        edit_menu.add_command(label="Redo", command=self.menu_redo)
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self.menu_cut)
        edit_menu.add_command(label="Copy", command=self.menu_copy)
        edit_menu.add_command(label="Paste", command=self.menu_paste)
        edit_menu.add_separator()
        edit_menu.add_command(label="Select All", command=self.menu_select_all)
        edit_menu.add_command(label="Clear", command=self.menu_clear)

                   
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Clear Chat", command=self.menu_clear_chat)
        view_menu.add_separator()
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme('light'))
        view_menu.add_command(label="Dark Theme", command=lambda: self.set_theme('dark'))
        view_menu.add_command(label="System Default", command=lambda: self.set_theme('auto'))
        view_menu.add_separator()
        view_menu.add_command(label="Settings", command=self.menu_settings)

                   
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.menu_about)
        help_menu.add_command(label="Help Contents", command=self.menu_help)

    def set_theme(self, theme: str):
        """sets application theme and saves preference"""
        if theme == 'auto':
            actual_theme = ThemeManager.detect_system_theme()
        else:
            actual_theme = theme
        
        self.current_theme = theme
        self.apply_theme(actual_theme)
        ThemeManager.save_theme_preference(theme, theme == 'auto')
        self.display_message_system(f"theme changed to {actual_theme}")
    
    def menu_new(self):
        """placeholder for new menu item"""
        messagebox.showinfo("New", "New document - placeholder")

    def menu_open(self):
        """placeholder for open menu item"""
        messagebox.showinfo("Open", "Open file - placeholder")

    def menu_save(self):
        """Saves current settings to the default encrypted settings file."""
        if not self.nick:
            messagebox.showwarning("Warning", "No connection configured. Please configure connection first.")
            return
        
                                                        
        password = simpledialog.askstring("Master Password", 
            "Enter a master password to encrypt these settings:", show='*')
        if not password:
            messagebox.showwarning("Cancelled", "Settings save cancelled.")
            return
        
                                    
        settings = SettingsManager.create_settings_dict(
            server=self.server_entry.get(),
            port=int(self.port_entry.get()),
            nick=self.nick_entry.get(),
            channel=self.channel_entry.get(),
            password="",                          
            rotation_key=self.rotation_key,
            use_rotation=self.use_rotation,
            use_tor=self.use_tor,
            encrypt_names=self.encrypt_names
        )
        
                       
        if SettingsManager.save_settings(settings, password):
            messagebox.showinfo("Success", "Settings saved successfully to:\n" + 
                              SettingsManager.DEFAULT_SETTINGS_FILE)
            self.display_message_system("Settings saved to default location.")
        else:
            messagebox.showerror("Error", "Failed to save settings.")

    def menu_save_as(self):
        """Saves current settings to a custom file location."""
        if not self.nick:
            messagebox.showwarning("Warning", "No connection configured. Please configure connection first.")
            return
        
                               
        filepath = filedialog.asksaveasfilename(
            defaultextension=".lsconf",
            filetypes=[("LibreSilent Config", "*.lsconf"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not filepath:
            return
        
                                    
        password = simpledialog.askstring("Master Password", 
            "Enter a master password to encrypt these settings:", show='*')
        if not password:
            messagebox.showwarning("Cancelled", "Settings export cancelled.")
            return
        
                                    
        settings = SettingsManager.create_settings_dict(
            server=self.server_entry.get(),
            port=int(self.port_entry.get()),
            nick=self.nick_entry.get(),
            channel=self.channel_entry.get(),
            password="",                          
            rotation_key=self.rotation_key,
            use_rotation=self.use_rotation,
            use_tor=self.use_tor,
            encrypt_names=self.encrypt_names
        )
        
                         
        if SettingsManager.export_settings(settings, password, filepath):
            messagebox.showinfo("Success", f"Settings exported successfully to:\n{filepath}")
            self.display_message_system(f"Settings exported to {filepath}")
        else:
            messagebox.showerror("Error", "Failed to export settings.")

    def menu_undo(self):
        """placeholder for undo menu item"""
        messagebox.showinfo("Undo", "Undo action - placeholder")

    def menu_redo(self):
        """placeholder for redo menu item"""
        messagebox.showinfo("Redo", "Redo action - placeholder")

    def menu_cut(self):
        """placeholder for cut menu item"""
        messagebox.showinfo("Cut", "Cut text - placeholder")

    def menu_copy(self):
        """placeholder for copy menu item"""
        messagebox.showinfo("Copy", "Copy text - placeholder")

    def menu_paste(self):
        """placeholder for paste menu item"""
        messagebox.showinfo("Paste", "Paste text - placeholder")

    def menu_select_all(self):
        """placeholder for select all menu item"""
        messagebox.showinfo("Select All", "Select all text - placeholder")

    def menu_clear(self):
        """placeholder for clear menu item"""
        messagebox.showinfo("Clear", "Clear text - placeholder")

    def menu_clear_chat(self):
        """clears chat window"""
        self.chat_window.config(state='normal')
        self.chat_window.delete(1.0, tk.END)
        self.chat_window.config(state='disabled')
        self.display_message_system("Chat cleared.")

    def menu_settings(self):
        """displays settings dialog with import/export options"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings & Configuration")
        settings_window.geometry("400x250")
        settings_window.transient(self.root)
        settings_window.config(bg=self.colors['bg'])
        
        frame = ttk.Frame(settings_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Settings Management", font=("Arial", 14, "bold")).pack(pady=10)
        
        def on_import():
            self.import_settings_from_file()
            settings_window.destroy()
        
        ttk.Button(frame, text="Import Settings from File", command=on_import).pack(fill=tk.X, pady=5)
        
        def on_export():
            self.menu_save_as()
            settings_window.destroy()
        
        ttk.Button(frame, text="Export Settings to File", command=on_export).pack(fill=tk.X, pady=5)
        
        def on_save():
            self.menu_save()
            settings_window.destroy()
        
        ttk.Button(frame, text="Save to Default Location", command=on_save).pack(fill=tk.X, pady=5)
        
        def on_view():
            self.view_current_settings()
        
        ttk.Button(frame, text="View Current Settings", command=on_view).pack(fill=tk.X, pady=5)
        
        ttk.Button(frame, text="Close", command=settings_window.destroy).pack(fill=tk.X, pady=5)

    def menu_about(self):
        """displays about dialog"""
        messagebox.showinfo("About", "LibreSilent - Encrypted IRC Client\nVersion 1.0\n\nA secure communication tool using encrypted IRC.")

    def menu_help(self):
        """displays help/welcome dialog"""
        self.show_welcome_dialog()

    def import_settings_from_file(self):
        """imports settings from encrypted file and populates ui"""
        filepath = filedialog.askopenfilename(
            filetypes=[("LibreSilent Config", "*.lsconf"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not filepath:
            return
        
        password = simpledialog.askstring("Master Password", 
            "Enter the master password to decrypt these settings:", show='*')
        if not password:
            messagebox.showwarning("Cancelled", "Settings import cancelled.")
            return
        
        settings = SettingsManager.import_settings(password, filepath)
        
        if not settings:
            messagebox.showerror("Error", "Failed to import settings. Password may be incorrect.")
            return
        
        try:
            self.server_entry.config(state='normal')
            self.server_entry.delete(0, tk.END)
            self.server_entry.insert(0, settings.get('server', 'irc.libera.chat'))
            
            self.port_entry.config(state='normal')
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, str(settings.get('port', 6667)))
            
            self.nick_entry.config(state='normal')
            self.nick_entry.delete(0, tk.END)
            self.nick_entry.insert(0, settings.get('nick', 'EncryptedUser'))
            
            self.channel_entry.config(state='normal')
            self.channel_entry.delete(0, tk.END)
            self.channel_entry.insert(0, settings.get('channel', ''))
            self.channel_entry.config(state='disabled')
            
            self.use_tor = settings.get('use_tor', False)
            if self.use_tor:
                self.tor_button.config(relief=tk.SUNKEN)
            else:
                self.tor_button.config(relief=tk.RAISED)
            
            self.encrypt_names = settings.get('encrypt_names', True)
            if self.encrypt_names:
                self.encrypt_names_button.config(relief=tk.SUNKEN)
            else:
                self.encrypt_names_button.config(relief=tk.RAISED)
            
            self.use_rotation = settings.get('use_rotation', False)
            self.rotation_key = settings.get('rotation_key')
            if self.use_rotation:
                self.rotation_button.config(relief=tk.SUNKEN)
            else:
                self.rotation_button.config(relief=tk.RAISED)
            
            messagebox.showinfo("Success", f"Settings imported successfully from:\n{filepath}")
            self.display_message_system(f"Settings imported from {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply imported settings: {e}")

    def view_current_settings(self):
        """displays current settings in readable format"""
        settings_view = tk.Toplevel(self.root)
        settings_view.title("Current Settings")
        settings_view.geometry("500x400")
        settings_view.transient(self.root)
        settings_view.config(bg=self.colors['bg'])
        
        frame = ttk.Frame(settings_view, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = scrolledtext.ScrolledText(frame, wrap=tk.WORD, state='normal', **self.get_text_style())
        text_widget.pack(fill=tk.BOTH, expand=True, pady=10)
        
        settings_text = f"""Current LibreSilent Settings
{'='*40}

SERVER CONFIGURATION:
  Server: {self.server_entry.get()}
  Port: {self.port_entry.get()}
  Nick: {self.nick_entry.get()}
  Channel: {self.channel_entry.get()}

SECURITY OPTIONS:
  Encrypt Names: {'Yes' if self.encrypt_names else 'No'}
  Use Code Rotation: {'Yes' if self.use_rotation else 'No'}
  Rotation Start Date: {datetime.datetime.now().strftime("%Y%m%d") if self.use_rotation else 'N/A'}

NETWORK OPTIONS:
  Use TOR: {'Yes' if self.use_tor else 'No'}
  TOR Port: {self.tor_port if self.use_tor else 'N/A'}

CUSTOM CHANNEL:
  Using Custom Channel: {'Yes' if self.using_custom_channel else 'No'}

CONNECTION STATUS:
  Connected: {'Yes' if self.is_ready_to_send else 'No'}
  
NOTES:
- Settings can be exported and imported using File > Save/Import
- Use a strong master password when saving settings
- Both parties must use identical encryption keys to communicate
"""
        text_widget.insert(1.0, settings_text)
        text_widget.config(state='disabled')
        
        ttk.Button(frame, text="Close", command=settings_view.destroy).pack(pady=10)


    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted IRC Client")
        self.root.attributes('-zoomed', True)
        self.original_title = self.root.title()
        
                          
        self.current_theme = ThemeManager.load_theme_preference()
        self.apply_theme(self.current_theme)
        
                                 
        self.use_tor = False
        self.tor_port = 9050
        
                         
        self.create_menu_bar()
        
                             
        self.root.after(500, self.show_welcome_dialog)
        
                                        
        if HAS_NOTIFICATIONS:
            if platform.system() == "Linux":
                notify2.init("LibreSilent")
            elif platform.system() == "Windows":
                self.toaster = ToastNotifier()

                                      
        self.settings_frame = tk.Frame(root, pady=5, **self.get_frame_style())
        self.settings_frame.pack(fill='x')

        tk.Label(self.settings_frame, text="Server:", **self.get_label_style()).pack(side=tk.LEFT, padx=5)
        self.server_entry = tk.Entry(self.settings_frame, width=15, **self.get_entry_style())
        self.server_entry.insert(0, "irc.libera.chat")
        self.server_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Port:", **self.get_label_style()).pack(side=tk.LEFT, padx=5)
        self.port_entry = tk.Entry(self.settings_frame, width=5, **self.get_entry_style())
        self.port_entry.insert(0, "6667")
        self.port_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Nick:", **self.get_label_style()).pack(side=tk.LEFT, padx=5)
        self.nick_entry = tk.Entry(self.settings_frame, width=10, **self.get_entry_style())
        self.nick_entry.insert(0, "EncryptedUser")
        self.nick_entry.pack(side=tk.LEFT)

        tk.Label(self.settings_frame, text="Channel:", **self.get_label_style()).pack(side=tk.LEFT, padx=5)
        self.channel_entry = tk.Entry(self.settings_frame, width=10, **self.get_entry_style())
        self.channel_entry.insert(0, "")
        self.channel_entry.config(state='disabled')
        self.channel_entry.pack(side=tk.LEFT)

                               
        self.custom_channel_button = tk.Button(self.settings_frame, text="Custom Channel", command=self.toggle_custom_channel, **self.get_button_style())
        self.custom_channel_button.pack(side=tk.LEFT, padx=5)
        self.using_custom_channel = False

                                     
        self.encrypt_names_button = tk.Button(self.settings_frame, text="Encrypt Names", command=self.toggle_name_encryption, **self.get_button_style())
        self.encrypt_names_button.pack(side=tk.LEFT, padx=5)
        self.encrypt_names = True
        self.encrypt_names_button.config(relief=tk.SUNKEN)

                                   
        self.tor_button = tk.Button(self.settings_frame, text="Use TOR", command=self.toggle_tor, **self.get_button_style())
        self.tor_button.pack(side=tk.LEFT, padx=5)

                                     
        self.use_rotation = False
        self.rotation_key = None
        self.rotation_button = tk.Button(self.settings_frame, text="Code Rotation", command=self.toggle_rotation, **self.get_button_style())
        self.rotation_button.pack(side=tk.LEFT, padx=5)
        
                                   
        self.connect_button = tk.Button(self.settings_frame, text="Connect", command=self.connect, **self.get_button_style())
        self.connect_button.pack(side=tk.RIGHT, padx=5)

                                            
        self.chat_window = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD, relief=tk.SUNKEN, borderwidth=1, **self.get_text_style())
        self.chat_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

                                              
        self.bottom_frame = tk.Frame(root, pady=5, **self.get_frame_style())
        self.bottom_frame.pack(fill='x')

        self.message_entry = tk.Entry(self.bottom_frame, state='disabled', **self.get_entry_style())
        self.message_entry.pack(fill='x', expand=True, side=tk.LEFT, padx=5)
        self.message_entry.bind("<Return>", self.send_message_event)

        self.send_button = tk.Button(self.bottom_frame, text="Send", command=self.send_message_event, **self.get_button_style())
        self.send_button.pack(side=tk.RIGHT, padx=5)

                                 
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

                                          
        password = simpledialog.askstring("Secret Key", "Enter your shared secret password:", show='*')
        if not password:
            self.display_message_system("Connection cancelled. No key provided.")
            return

                                                         
        if self.use_rotation:
            rotation_key = simpledialog.askstring("Rotation Key", 
                "Enter your secondary rotation key:", show='*')
            if not rotation_key:
                self.display_message_system("Connection cancelled. No rotation key provided.")
                return
            self.rotation_key = rotation_key
            self.display_message_system("Code rotation active - keys will rotate daily")
        
        self.encryption_key = derive_key(password, self.rotation_key, self.use_rotation)
        
        if self.using_custom_channel:
            self.channel = self.channel_entry.get()
            if not self.channel:
                messagebox.showerror("Error", "Custom channel name is required.")
                return
            if not self.channel.startswith('#'):
                self.channel = f"#{self.channel}"
        else:
                                                       
            channel_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
            self.channel = f"#ls{channel_hash}"                                 
            self.channel_entry.config(state='normal')
            self.channel_entry.delete(0, tk.END)
            self.channel_entry.insert(0, self.channel)
            self.channel_entry.config(state='disabled')
        
        self.display_message_system(f"Key derived. Using channel {self.channel}")
        self.display_message_system(f"Connecting to {server}...")

                          
        self.server_entry.config(state='disabled')
        self.port_entry.config(state='disabled')
        self.nick_entry.config(state='disabled')
        self.channel_entry.config(state='disabled')
        self.connect_button.config(text="Connecting...", state='disabled')

                              
        self.irc_thread = IRCHandler(server, port, self.nick, self.channel, self.gui_queue, 
                                   use_tor=self.use_tor, tor_port=self.tor_port)
        self.irc_thread.start()

        if self.use_tor:
            self.display_message_system("Connecting through TOR network...")
        
                                                   
        self.root.after(100, self.check_queue)

    def disconnect(self):
        """stops irc thread and resets application"""
        if self.irc_thread:
            self.display_message_system("Sending QUIT command to server and disconnecting...")
            self.irc_thread.stop()
            self.irc_thread = None
        self._reset_ui()
        self.display_message_system("Disconnected.")

    def check_queue(self):
        """checks queue for messages from irc thread"""
        while not self.gui_queue.empty():
            sender, message = self.gui_queue.get_nowait()
            self.handle_incoming(sender, message)

        if self.irc_thread and not self.irc_thread.is_alive() and self.is_ready_to_send:
            self.gui_queue.put(('SYSTEM_ERROR', "Connection thread unexpectedly terminated."))

        self.root.after(100, self.check_queue)

    def handle_incoming(self, sender, message):
        """decrypts and displays incoming message, handles system errors"""
        if sender == 'SYSTEM_ERROR':
            self.display_message_error(message)
            self._reset_ui()
            return
        elif sender == 'SYSTEM_MESSAGE':
            self.display_message_system(message)
            if "Successfully joined" in message:
                self.is_ready_to_send = True
                self.message_entry.config(state='normal')
                self.connect_button.config(text="Disconnect", bg="salmon", state='normal', command=self.disconnect)
            return

        decrypted = decrypt_message(message, self.encryption_key)
        
        displayed_sender = sender
        if self.encrypt_names and sender != self.nick:
            try:
                decrypted_sender = decrypt_message(sender, self.encryption_key)
                if decrypted_sender:
                    displayed_sender = decrypted_sender
            except Exception:
                pass

        if decrypted:
            display = f"<{displayed_sender}> {decrypted}"
            self.display_message(display)

            self.show_notification("New Message", f"Message from {displayed_sender}")

            self.root.title(f"** NEW MESSAGE ** - {self.original_title}")

        else:
            self.display_message_system(f"<{sender}> [Unencrypted or corrupt message]")

    def send_message_event(self, event=None):
        """handles send button click or enter key press"""
        message = self.message_entry.get()

        if self.root.title().startswith("** NEW MESSAGE **"):
            self.root.title(self.original_title)

        if message and self.irc_thread and self.encryption_key and self.is_ready_to_send:
            encrypted_message = encrypt_message(message, self.encryption_key)
            self.irc_thread.send_privmsg(encrypted_message)

            if self.encrypt_names:
                encrypted_nick = encrypt_message(self.nick, self.encryption_key)
                self.irc_thread.nick = encrypted_nick
                
            self.display_message(f"<{self.nick}> {message}")

            self.message_entry.delete(0, tk.END)
        elif message and not self.is_ready_to_send:
             self.display_message_system("Please wait for the channel join message before sending.")


    def display_message(self, message):
        """inserts message into chat window"""
        self.chat_window.config(state='normal')
        self.chat_window.insert(tk.END, message + "\n")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END)

    def display_message_system(self, message):
        """displays system message in themed color"""
        self.chat_window.config(state='normal')
        self.chat_window.tag_configure("system", foreground=self.colors['system_fg'], font=("Arial", 10, "italic"))
        self.chat_window.insert(tk.END, message + "\n", "system")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END)

    def display_message_error(self, message):
        """displays critical error message in special format"""
        self.chat_window.config(state='normal')
        self.chat_window.tag_configure("error", foreground=self.colors['error_fg'], font=("Arial", 10, "bold"))
        self.chat_window.insert(tk.END, "--- CRITICAL ERROR ---\n", "error")
        self.chat_window.insert(tk.END, message + "\n", "error")
        self.chat_window.insert(tk.END, "----------------------\n", "error")
        self.chat_window.config(state='disabled')
        self.chat_window.yview(tk.END)

    def show_notification(self, title, message):
        """shows system notification"""
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
            print(f"failed to show notification: {e}")

    def check_tor_connection(self):
        """checks if tor is running and accessible"""
        try:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            sock.settimeout(5)
            sock.connect(("check.torproject.org", 443))
            sock.close()
            return True
        except Exception:
            return False

    def toggle_tor(self):
        """toggles tor network usage"""
        if not self.use_tor:
            if self.check_tor_connection():
                self.use_tor = True
                self.tor_button.config(relief=tk.SUNKEN)
                self.display_message_system("TOR routing enabled")
            else:
                messagebox.showerror("Error", 
                    "Could not connect to TOR. Make sure TOR is running and listening on port 9050.")
        else:
            self.use_tor = False
            self.tor_button.config(relief=tk.RAISED)
            self.display_message_system("TOR routing disabled")

    def toggle_name_encryption(self):
        """toggles encryption of usernames"""
        self.encrypt_names = not self.encrypt_names
        if self.encrypt_names:
            self.encrypt_names_button.config(relief=tk.SUNKEN)
            self.display_message_system("Name encryption enabled")
        else:
            self.encrypt_names_button.config(relief=tk.RAISED)
            self.display_message_system("Name encryption disabled")
            
    def toggle_rotation(self):
        """toggles daily code rotation feature"""
        self.use_rotation = not self.use_rotation
        if self.use_rotation:
            self.rotation_button.config(relief=tk.SUNKEN)
            self.display_message_system("Daily code rotation enabled")
        else:
            self.rotation_button.config(relief=tk.RAISED)
            self.display_message_system("Daily code rotation disabled")

    def toggle_custom_channel(self):
        """toggles between custom and auto-generated channel"""
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
        """resets ui elements and state variables after disconnection or error"""
        self.server_entry.config(state='normal')
        self.port_entry.config(state='normal')
        self.nick_entry.config(state='normal')
        if not self.using_custom_channel:
            self.channel_entry.config(state='disabled')

        self.connect_button.config(text="Connect", state='normal', bg=self.colors['button_bg'], command=self.connect)

        self.irc_thread = None
        self.encryption_key = None
        self.is_ready_to_send = False
        self.message_entry.config(state='disabled')
        self.root.title(self.original_title)

    def on_closing(self):
        """stops irc thread and closes application"""
        if self.irc_thread:
            self.irc_thread.stop()
        self.root.destroy()

                        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LibreSilent - Encrypted IRC Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py              # Launch GUI mode (default)
  python main.py -nogui       # Launch terminal-based UI mode
  python main.py --help       # Show this help message
        """
    )
    parser.add_argument('-nogui', '--no-gui', action='store_true', dest='no_gui',
                       help='Run in terminal mode without GUI')
    
    args = parser.parse_args()
    
    if args.no_gui:
        # Terminal UI mode
        terminal_app = TerminalUIHandler()
        terminal_app.connect()
    else:
        # GUI mode
        root = tk.Tk()
        app = EncryptedIRCClient(root)
        root.mainloop()
