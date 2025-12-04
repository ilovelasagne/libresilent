#!/usr/bin/env python3
"""
LibreSilent - Encrypted IRC Client (Qt-based GUI)
A beautiful, modern implementation using PyQt5
"""

import sys
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
import yaml
import subprocess
from cryptography.fernet import Fernet, InvalidToken
try:
    from pypresence import Presence
    HAS_DISCORD_RPC = True
except ImportError:
    HAS_DISCORD_RPC = False

try:
    import spotipy
    from spotipy.oauth2 import SpotifyClientCredentials
    HAS_SPOTIFY = True
except ImportError:
    HAS_SPOTIFY = False

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFrame, QTabWidget,
    QDialog, QScrollArea, QCheckBox, QComboBox, QSpinBox, QMessageBox,
    QFileDialog, QInputDialog, QStatusBar, QSplitter
)
from PyQt5.QtCore import (
    Qt, QTimer, pyqtSignal, QObject, QSize, QRect,
    QPropertyAnimation, QEasingCurve, QThread, QEvent
)
from PyQt5.QtGui import (
    QFont, QColor, QIcon, QPalette, QTextCursor, QPixmap,
    QLinearGradient, QBrush, QPainter, QPen
)
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu

if platform.system() == "Linux":
    try:
        import notify2
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
elif platform.system() == "Darwin":
    HAS_NOTIFICATIONS = True
elif platform.system() == "Windows":
    try:
        from win10toast import ToastNotifier
        HAS_NOTIFICATIONS = True
    except ImportError:
        HAS_NOTIFICATIONS = False
else:
    HAS_NOTIFICATIONS = False

SALT = b'encrypted-irc-salt-v1'


# ============================================================================
# SINGLE INSTANCE LOCK
# ============================================================================

class SingleInstanceLock:
    """Ensures only one instance of the application runs"""
    
    def __init__(self, name="libresilent"):
        self.name = name
        self.lock_file = os.path.expanduser(f"~/.{name}.lock")
        self.lock_socket = None
        self.acquired = False
    
    def acquire(self):
        """Try to acquire the lock"""
        try:
            # Create lock file if it doesn't exist
            if os.path.exists(self.lock_file):
                try:
                    with open(self.lock_file, 'r') as f:
                        old_pid = int(f.read().strip())
                    # Check if process is still running
                    try:
                        os.kill(old_pid, 0)
                        # Process is running, can't start
                        return False
                    except ProcessLookupError:
                        # Process not running, remove old lock
                        os.remove(self.lock_file)
                except:
                    pass
            
            # Write current PID to lock file
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            
            self.acquired = True
            return True
        except Exception as e:
            print(f"Error acquiring lock: {e}")
            return False
    
    def release(self):
        """Release the lock"""
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
            self.acquired = False
        except Exception as e:
            print(f"Error releasing lock: {e}")


# ============================================================================
# ENCRYPTION & KEY DERIVATION
# ============================================================================

SALT = b'encrypted-irc-salt-v1'

SALT = b'encrypted-irc-salt-v1'

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


def encrypt_message_double(message: str, key: bytes) -> str:
    """encrypts message using AES-256-CBC twice (double encryption)"""
    f = Fernet(key)
    first_encrypted = f.encrypt(message.encode('utf-8'))
    second_encrypted = f.encrypt(first_encrypted)
    return second_encrypted.decode('utf-8')


def decrypt_message_double(token: str, key: bytes) -> str | None:
    """decrypts double-encrypted message, returns None on failure"""
    try:
        f = Fernet(key)
        first_decrypted = f.decrypt(token.encode('utf-8'))
        decrypted_message = f.decrypt(first_decrypted)
        return decrypted_message.decode('utf-8')
    except (InvalidToken, TypeError, Exception):
        return None


# ============================================================================
# SETTINGS MANAGER
# ============================================================================

class SettingsManager:
    """handles encryption and persistence of application settings"""
    
    CONFIG_DIR = os.path.expanduser('~/.config/libresilent')
    DEFAULT_SETTINGS_FILE = os.path.join(CONFIG_DIR, 'settings.json')
    CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.yml')
    FRIENDS_FILE = os.path.join(CONFIG_DIR, 'friends.json')
    PROFILE_FILE = os.path.join(CONFIG_DIR, 'profile.json')
    CHATS_FILE = os.path.join(CONFIG_DIR, 'chats.json')
    
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
    def save_friends(friends_dict: dict) -> bool:
        """saves friends list to file"""
        try:
            SettingsManager.ensure_config_dir()
            with open(SettingsManager.FRIENDS_FILE, 'w') as f:
                json.dump(friends_dict, f, indent=2)
            return True
        except Exception as e:
            print(f"error saving friends: {e}")
            return False
    
    @staticmethod
    def load_friends() -> dict:
        """loads friends list from file"""
        try:
            if os.path.exists(SettingsManager.FRIENDS_FILE):
                with open(SettingsManager.FRIENDS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"error loading friends: {e}")
        return {}
    
    @staticmethod
    def save_profile(profile_dict: dict) -> bool:
        """saves user profile"""
        try:
            SettingsManager.ensure_config_dir()
            with open(SettingsManager.PROFILE_FILE, 'w') as f:
                json.dump(profile_dict, f, indent=2)
            return True
        except Exception as e:
            print(f"error saving profile: {e}")
            return False
    
    @staticmethod
    def load_profile() -> dict:
        """loads user profile"""
        try:
            if os.path.exists(SettingsManager.PROFILE_FILE):
                with open(SettingsManager.PROFILE_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"error loading profile: {e}")
        return {'username': '', 'friend_code': '', 'friends_enabled': False, 'online': False}
    
    @staticmethod
    def save_chats(chats_dict: dict) -> bool:
        """saves chats list to file"""
        try:
            SettingsManager.ensure_config_dir()
            with open(SettingsManager.CHATS_FILE, 'w') as f:
                json.dump(chats_dict, f, indent=2)
            return True
        except Exception as e:
            print(f"error saving chats: {e}")
            return False
    
    @staticmethod
    def load_chats() -> dict:
        """loads chats list from file"""
        try:
            if os.path.exists(SettingsManager.CHATS_FILE):
                with open(SettingsManager.CHATS_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"error loading chats: {e}")
        return {}
    
    @staticmethod
    def save_config_yaml(config_dict: dict) -> bool:
        """saves all application configuration to config.yml"""
        try:
            SettingsManager.ensure_config_dir()
            with open(SettingsManager.CONFIG_FILE, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)
            return True
        except Exception as e:
            print(f"error saving config.yml: {e}")
            return False
    
    @staticmethod
    def load_config_yaml() -> dict:
        """loads all application configuration from config.yml"""
        try:
            if os.path.exists(SettingsManager.CONFIG_FILE):
                with open(SettingsManager.CONFIG_FILE, 'r') as f:
                    config = yaml.safe_load(f)
                    return config if config else {}
        except Exception as e:
            print(f"error loading config.yml: {e}")
        return {}
    
    @staticmethod
    def export_config_to_yaml(settings_dict: dict, friends_dict: dict, 
                              profile_dict: dict, chats_dict: dict,
                              preferences_dict: dict = None) -> dict:
        """consolidates all settings into a single config dictionary"""
        if preferences_dict is None:
            preferences_dict = {}
        
        return {
            'application': {
                'version': '1.0',
                'last_updated': datetime.datetime.now().isoformat(),
            },
            'connection': {
                'server': settings_dict.get('server', ''),
                'port': settings_dict.get('port', 6667),
                'nick': settings_dict.get('nick', ''),
                'channel': settings_dict.get('channel', ''),
                'use_tor': settings_dict.get('use_tor', False),
                'use_rotation': settings_dict.get('use_rotation', False),
                'encrypt_names': settings_dict.get('encrypt_names', True),
            },
            'preferences': {
                'theme': preferences_dict.get('theme', 'auto'),
                'show_timestamps': preferences_dict.get('show_timestamps', True),
                'enable_animations': preferences_dict.get('enable_animations', False),
                'enable_notifications': preferences_dict.get('enable_notifications', True),
                'enable_notification_sounds': preferences_dict.get('enable_notification_sounds', True),
                'auto_save_settings': preferences_dict.get('auto_save_settings', False),
                'friends_enabled': preferences_dict.get('friends_enabled', False),
                'close_to_tray': preferences_dict.get('close_to_tray', False),
            },
            'profile': profile_dict,
            'friends': friends_dict,
            'chats': chats_dict,
        }
    
    @staticmethod
    def import_config_from_yaml(config_dict: dict) -> tuple:
        """extracts individual configuration sections from consolidated config"""
        settings = {
            'server': config_dict.get('connection', {}).get('server', ''),
            'port': config_dict.get('connection', {}).get('port', 6667),
            'nick': config_dict.get('connection', {}).get('nick', ''),
            'channel': config_dict.get('connection', {}).get('channel', ''),
            'use_tor': config_dict.get('connection', {}).get('use_tor', False),
            'use_rotation': config_dict.get('connection', {}).get('use_rotation', False),
            'encrypt_names': config_dict.get('connection', {}).get('encrypt_names', True),
            'theme': config_dict.get('preferences', {}).get('theme', 'auto'),
        }
        friends = config_dict.get('friends', {})
        profile = config_dict.get('profile', {})
        chats = config_dict.get('chats', {})
        preferences = config_dict.get('preferences', {})
        
        return settings, friends, profile, chats, preferences


# ============================================================================
# THEME MANAGER
# ============================================================================

class ThemeManager:
    """handles application theming and styling"""
    
    DARK_STYLESHEET = """
    QMainWindow, QDialog, QWidget {
        background-color: #1e1e1e;
        color: #ffffff;
    }
    
    QLineEdit, QTextEdit, QComboBox {
        background-color: #2b2b2b;
        color: #ffffff;
        border: 1px solid #404040;
        border-radius: 4px;
        padding: 4px;
        selection-background-color: #0d47a1;
    }
    
    QPushButton {
        background-color: #0d47a1;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        padding: 6px 12px;
        font-weight: bold;
    }
    
    QPushButton:hover {
        background-color: #1565c0;
    }
    
    QPushButton:pressed {
        background-color: #0d3a8f;
    }
    
    QTabWidget::pane {
        border: 1px solid #404040;
    }
    
    QTabBar::tab {
        background-color: #2d2d2d;
        color: #ffffff;
        padding: 6px 20px;
        border: 1px solid #404040;
    }
    
    QTabBar::tab:selected {
        background-color: #0d47a1;
        border: 1px solid #0d47a1;
    }
    
    QCheckBox {
        color: #ffffff;
        spacing: 5px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
    }
    
    QCheckBox::indicator:unchecked {
        background-color: #2b2b2b;
        border: 1px solid #404040;
    }
    
    QCheckBox::indicator:checked {
        background-color: #0d47a1;
        border: 1px solid #0d47a1;
    }
    
    QStatusBar {
        background-color: #2d2d2d;
        color: #ffffff;
        border-top: 1px solid #404040;
    }
    
    QScrollBar:vertical {
        background-color: #2b2b2b;
        width: 12px;
        border: none;
    }
    
    QScrollBar::handle:vertical {
        background-color: #404040;
        border-radius: 6px;
        min-height: 20px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #505050;
    }
    """
    
    LIGHT_STYLESHEET = """
    QMainWindow, QDialog, QWidget {
        background-color: #ffffff;
        color: #000000;
    }
    
    QLineEdit, QTextEdit, QComboBox {
        background-color: #f5f5f5;
        color: #000000;
        border: 1px solid #cccccc;
        border-radius: 4px;
        padding: 4px;
        selection-background-color: #2196F3;
    }
    
    QPushButton {
        background-color: #2196F3;
        color: #ffffff;
        border: none;
        border-radius: 4px;
        padding: 6px 12px;
        font-weight: bold;
    }
    
    QPushButton:hover {
        background-color: #1976D2;
    }
    
    QPushButton:pressed {
        background-color: #1565c0;
    }
    
    QTabWidget::pane {
        border: 1px solid #e0e0e0;
    }
    
    QTabBar::tab {
        background-color: #eeeeee;
        color: #000000;
        padding: 6px 20px;
        border: 1px solid #e0e0e0;
    }
    
    QTabBar::tab:selected {
        background-color: #2196F3;
        color: #ffffff;
        border: 1px solid #2196F3;
    }
    
    QCheckBox {
        color: #000000;
        spacing: 5px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
    }
    
    QCheckBox::indicator:unchecked {
        background-color: #f5f5f5;
        border: 1px solid #cccccc;
    }
    
    QCheckBox::indicator:checked {
        background-color: #2196F3;
        border: 1px solid #2196F3;
    }
    
    QStatusBar {
        background-color: #f5f5f5;
        color: #000000;
        border-top: 1px solid #e0e0e0;
    }
    
    QScrollBar:vertical {
        background-color: #f5f5f5;
        width: 12px;
        border: none;
    }
    
    QScrollBar::handle:vertical {
        background-color: #bdbdbd;
        border-radius: 6px;
        min-height: 20px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #9e9e9e;
    }
    """
    
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
    def get_stylesheet(theme: str) -> str:
        """get stylesheet for theme"""
        return ThemeManager.DARK_STYLESHEET if theme == 'dark' else ThemeManager.LIGHT_STYLESHEET


# ============================================================================
# IRC HANDLER
# ============================================================================

class IRCHandler(QThread):
    """Handles IRC connection in a separate thread"""
    
    message_received = pyqtSignal(str, str)  # sender, message
    system_message = pyqtSignal(str)  # message
    system_error = pyqtSignal(str)  # error message
    connected = pyqtSignal()  # when successfully joined channel
    
    def __init__(self, server, port, nick, channel, use_tor=False, tor_port=9050):
        super().__init__()
        self.server = server
        self.port = port
        self.nick = nick
        self.channel = channel
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.running = True
        
        if self.use_tor:
            self.sock = socks.socksocket()
            self.sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.sock.settimeout(5)
    
    def run(self):
        """Main thread loop"""
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
                        self.connected.emit()
                        self.send_command(f"JOIN {self.channel}")
                    
                    if line.startswith("PING"):
                        self.handle_ping(line)
                    elif "PRIVMSG" in line:
                        self.handle_privmsg(line)
                    elif not line.startswith(":"):
                        self.system_message.emit(line)
        
        except Exception as e:
            self.system_error.emit(f"Failed to connect: {e}")
        finally:
            self.stop()
    
    def send_command(self, command):
        """Sends a raw command to the IRC server"""
        if self.running:
            try:
                self.sock.send(f"{command}\r\n".encode('utf-8'))
            except:
                pass
    
    def send_privmsg(self, message):
        """Sends an encrypted message to the channel"""
        self.send_command(f"PRIVMSG {self.channel} :{message}")
    
    def handle_ping(self, line):
        """Responds to server PINGs"""
        server = line.split(":")[-1]
        self.send_command(f"PONG :{server}")
    
    def handle_privmsg(self, line):
        """Parses a PRIVMSG"""
        try:
            sender = line.split("!")[0][1:]
            message_content = line.split(":", 2)[-1]
            
            if self.channel in line and sender != self.nick:
                self.message_received.emit(sender, message_content)
        except Exception as e:
            print(f"Error parsing PRIVMSG: {e}")
    
    def stop(self):
        """Stops the connection thread"""
        self.running = False
        try:
            if self.sock.fileno() != -1:
                self.sock.send(f"QUIT :Client disconnecting\r\n".encode('utf-8'))
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
        except:
            pass


# ============================================================================
# ACTIVITY MONITOR THREAD
# ============================================================================

class ActivityMonitorThread(QThread):
    """Monitors Spotify and Discord RPC for user activity"""
    
    activity_updated = pyqtSignal(dict)  # Emits activity dict {source, title, artist/game, status}
    activity_cleared = pyqtSignal()  # Emits when no activity is detected
    
    def __init__(self, enable_discord=True, enable_spotify=True, discord_client_id=None):
        super().__init__()
        self.enable_discord = enable_discord and HAS_DISCORD_RPC
        self.enable_spotify = enable_spotify and HAS_SPOTIFY
        self.discord_client_id = discord_client_id or "1234567890123456789"
        self.running = True
        self.discord_rpc = None
        self.spotify_client = None
        self.current_user = None
        self.last_activity = None
    
    def run(self):
        """Main activity monitoring loop"""
        try:
            # Initialize Discord RPC
            if self.enable_discord:
                self.init_discord_rpc()
            
            # Initialize Spotify
            if self.enable_spotify:
                self.init_spotify()
            
            # Main monitoring loop
            while self.running:
                activity = self.get_current_activity()
                
                if activity:
                    if activity != self.last_activity:
                        self.activity_updated.emit(activity)
                        self.last_activity = activity
                else:
                    if self.last_activity is not None:
                        self.activity_cleared.emit()
                        self.last_activity = None
                
                self.msleep(5000)  # Check every 5 seconds
                
        except Exception as e:
            print(f"Error in activity monitor: {e}")
        finally:
            self.cleanup()
    
    def init_discord_rpc(self):
        """Initialize Discord RPC connection"""
        try:
            if HAS_DISCORD_RPC:
                self.discord_rpc = Presence(self.discord_client_id)
                self.discord_rpc.connect()
        except Exception as e:
            print(f"Could not connect to Discord RPC: {e}")
            self.discord_rpc = None
    
    def init_spotify(self):
        """Initialize Spotify connection"""
        try:
            if HAS_SPOTIFY:
                # Try to use cached credentials or default auth
                # Spotipy will look for SPOTIPY_CLIENT_ID, SPOTIPY_CLIENT_SECRET, SPOTIPY_REDIRECT_URI env vars
                # Or use spotify-token cache
                try:
                    # Try to create a client with cached/default credentials
                    from spotipy.oauth2 import SpotifyOAuth
                    
                    sp_oauth = SpotifyOAuth(
                        client_id=os.getenv('SPOTIPY_CLIENT_ID'),
                        client_secret=os.getenv('SPOTIPY_CLIENT_SECRET'),
                        redirect_uri=os.getenv('SPOTIPY_REDIRECT_URI', 'http://localhost:8080'),
                        scope="user-read-currently-playing"
                    )
                    token = sp_oauth.get_cached_token()
                    if token:
                        self.spotify_client = spotipy.Spotify(auth=sp_oauth)
                    else:
                        # Try public API without auth for fallback
                        self.spotify_client = spotipy.Spotify()
                except:
                    # Fallback: try using generic Spotipy client
                    try:
                        self.spotify_client = spotipy.Spotify()
                    except:
                        self.spotify_client = None
        except Exception as e:
            print(f"Could not connect to Spotify: {e}")
            self.spotify_client = None
    
    def get_current_activity(self) -> dict | None:
        """Get current user activity from Discord, Spotify, or any media player"""
        activity = None
        
        # Try playerctl first (works with any media player)
        try:
            activity = self.get_playerctl_activity()
            if activity:
                return activity
        except:
            pass
        
        # Try Discord
        if self.discord_rpc:
            try:
                activity = self.get_discord_activity()
                if activity:
                    return activity
            except:
                pass
        
        # Try Spotify
        if self.spotify_client:
            try:
                activity = self.get_spotify_activity()
                if activity:
                    return activity
            except:
                pass
        
        return None
    
    def get_discord_activity(self) -> dict | None:
        """Get current Discord activity (game/stream)"""
        try:
            # Try to read from Discord's local IPC socket
            # This connects to the Discord desktop app's activity
            if self.discord_rpc and self.discord_rpc.is_connected():
                # Note: pypresence can't directly read, but we can try through alternative means
                # Check if Discord app has exposed activity data through IPC
                pass
        except:
            pass
        return None
    
    def get_spotify_activity(self) -> dict | None:
        """Get current Spotify activity"""
        try:
            if self.spotify_client:
                current_track = self.spotify_client.current_user_currently_playing()
                if current_track and current_track.get('item'):
                    item = current_track['item']
                    return {
                        'source': 'Spotify',
                        'title': item.get('name', 'Unknown Track'),
                        'artist': ', '.join([a['name'] for a in item.get('artists', [])]),
                        'status': 'Playing' if current_track.get('is_playing') else 'Paused'
                    }
        except:
            pass
        return None
    
    def get_playerctl_activity(self) -> dict | None:
        """Get current activity from any media player using playerctl"""
        try:
            # Get status
            status = subprocess.run(
                ['playerctl', 'status'],
                capture_output=True,
                text=True,
                timeout=2
            ).stdout.strip().lower()
            
            if not status or status not in ['playing', 'paused']:
                return None
            
            # Get metadata
            metadata = subprocess.run(
                ['playerctl', 'metadata', '--format', '{{title}}|{{artist}}|{{xesam:url}}'],
                capture_output=True,
                text=True,
                timeout=2
            ).stdout.strip()
            
            if not metadata:
                return None
            
            parts = metadata.split('|')
            title = parts[0] if len(parts) > 0 else 'Unknown'
            artist = parts[1] if len(parts) > 1 else ''
            
            # Try to determine player name
            player_name = subprocess.run(
                ['playerctl', 'metadata', 'mpris:source'],
                capture_output=True,
                text=True,
                timeout=2
            ).stdout.strip()
            
            if not player_name:
                player_name = 'Music Player'
            
            # Clean up player name (e.g., "spotify" -> "Spotify")
            player_name = player_name.split('.')[-1].capitalize()
            
            if title and title != 'Unknown':
                return {
                    'source': player_name,
                    'title': title,
                    'artist': artist,
                    'status': status.capitalize()
                }
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
            # playerctl not installed or timed out
            pass
        except Exception:
            pass
        return None
    
    def set_discord_activity(self, state: str, details: str = None, large_image: str = None):
        """Set our own Discord RPC presence"""
        try:
            if self.discord_rpc:
                self.discord_rpc.update(
                    state=state,
                    details=details,
                    large_image=large_image
                )
        except Exception as e:
            print(f"Error setting Discord activity: {e}")
    
    def stop(self):
        """Stop the activity monitor"""
        self.running = False
    
    def cleanup(self):
        """Cleanup connections"""
        try:
            if self.discord_rpc:
                self.discord_rpc.close()
        except:
            pass


# ============================================================================
# CONNECTION SETTINGS DIALOG
# ============================================================================

class ConnectionSettingsDialog(QDialog):
    """Modern dialog for connection settings"""
    
    def __init__(self, parent=None, theme='dark'):
        super().__init__(parent)
        self.theme = theme
        self.setWindowTitle("LibreSilent - Connection Settings")
        self.setGeometry(100, 100, 600, 700)
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Connection Settings")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Create tabs
        tabs = QTabWidget()
        
        # Server tab
        server_tab = QWidget()
        server_layout = QVBoxLayout()
        
        server_layout.addWidget(QLabel("IRC Server:"))
        self.server_input = QLineEdit()
        self.server_input.setText("irc.libera.chat")
        server_layout.addWidget(self.server_input)
        
        server_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()
        self.port_input.setText("6667")
        server_layout.addWidget(self.port_input)
        
        server_layout.addWidget(QLabel("Nickname:"))
        self.nick_input = QLineEdit()
        self.nick_input.setText("EncryptedUser")
        server_layout.addWidget(self.nick_input)
        
        server_layout.addStretch()
        server_tab.setLayout(server_layout)
        tabs.addTab(server_tab, "Server")
        
        # Security tab
        security_tab = QWidget()
        security_layout = QVBoxLayout()
        
        security_layout.addWidget(QLabel("Encryption Key:"))
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        security_layout.addWidget(self.key_input)
        
        self.rotation_check = QCheckBox("Enable Daily Code Rotation")
        security_layout.addWidget(self.rotation_check)
        
        security_layout.addWidget(QLabel("Rotation Key (if enabled):"))
        self.rotation_key_input = QLineEdit()
        self.rotation_key_input.setEchoMode(QLineEdit.Password)
        self.rotation_key_input.setEnabled(False)
        security_layout.addWidget(self.rotation_key_input)
        self.rotation_check.stateChanged.connect(
            lambda: self.rotation_key_input.setEnabled(self.rotation_check.isChecked())
        )
        
        self.double_encrypt_check = QCheckBox("Enable Double Encryption")
        security_layout.addWidget(self.double_encrypt_check)
        
        self.encrypt_names_check = QCheckBox("Encrypt Usernames")
        self.encrypt_names_check.setChecked(True)
        security_layout.addWidget(self.encrypt_names_check)
        
        security_layout.addStretch()
        security_tab.setLayout(security_layout)
        tabs.addTab(security_tab, "Security")
        
        # Channel tab
        channel_tab = QWidget()
        channel_layout = QVBoxLayout()
        
        self.auto_channel_check = QCheckBox("Use Auto-Generated Channel")
        self.auto_channel_check.setChecked(True)
        channel_layout.addWidget(self.auto_channel_check)
        
        channel_layout.addWidget(QLabel("Custom Channel (if disabled):"))
        self.channel_input = QLineEdit()
        self.channel_input.setEnabled(False)
        channel_layout.addWidget(self.channel_input)
        self.auto_channel_check.stateChanged.connect(
            lambda: self.channel_input.setEnabled(not self.auto_channel_check.isChecked())
        )
        
        channel_layout.addStretch()
        channel_tab.setLayout(channel_layout)
        tabs.addTab(channel_tab, "Channel")
        
        # Network tab
        network_tab = QWidget()
        network_layout = QVBoxLayout()
        
        self.tor_check = QCheckBox("Enable TOR Routing")
        network_layout.addWidget(self.tor_check)
        
        network_layout.addWidget(QLabel("TOR Port:"))
        self.tor_port_input = QLineEdit()
        self.tor_port_input.setText("9050")
        self.tor_port_input.setEnabled(False)
        network_layout.addWidget(self.tor_port_input)
        self.tor_check.stateChanged.connect(
            lambda: self.tor_port_input.setEnabled(self.tor_check.isChecked())
        )
        
        network_layout.addStretch()
        network_tab.setLayout(network_layout)
        tabs.addTab(network_tab, "Network")
        
        layout.addWidget(tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.connect_button = QPushButton("Connect")
        self.cancel_button = QPushButton("Cancel")
        
        self.connect_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)
    
    def get_settings(self):
        """Get settings from dialog"""
        return {
            'server': self.server_input.text(),
            'port': int(self.port_input.text()),
            'nick': self.nick_input.text(),
            'key': self.key_input.text(),
            'rotation_key': self.rotation_key_input.text() if self.rotation_check.isChecked() else None,
            'use_rotation': self.rotation_check.isChecked(),
            'double_encrypt': self.double_encrypt_check.isChecked(),
            'encrypt_names': self.encrypt_names_check.isChecked(),
            'auto_channel': self.auto_channel_check.isChecked(),
            'channel': self.channel_input.text() if not self.auto_channel_check.isChecked() else None,
            'use_tor': self.tor_check.isChecked(),
            'tor_port': int(self.tor_port_input.text()) if self.tor_check.isChecked() else 9050,
        }


# ============================================================================
# DIRECT MESSAGE DIALOG
# ============================================================================

class DirectMessageDialog(QDialog):
    """Direct message with a friend"""
    
    def __init__(self, parent=None, theme='dark', friend_name="", friend_code=""):
        super().__init__(parent)
        self.theme = theme
        self.friend_name = friend_name
        self.friend_code = friend_code
        self.setWindowTitle(f"LibreSilent - Chat with {friend_name}")
        self.setGeometry(100, 100, 600, 500)
        self.chat_key = None
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize direct message UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel(f"Chat with {self.friend_name}")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Encryption option
        enc_layout = QHBoxLayout()
        enc_layout.addWidget(QLabel("Use Friend Code for Encryption:"))
        self.use_code_check = QCheckBox()
        self.use_code_check.setChecked(True)
        enc_layout.addWidget(self.use_code_check)
        enc_layout.addStretch()
        layout.addLayout(enc_layout)
        
        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display, 1)
        
        # Message input
        msg_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type message...")
        msg_layout.addWidget(self.message_input)
        
        send_btn = QPushButton("Send")
        send_btn.setMaximumWidth(80)
        send_btn.clicked.connect(self.send_message)
        msg_layout.addWidget(send_btn)
        layout.addLayout(msg_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.setMaximumWidth(100)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def send_message(self):
        """Send message to friend"""
        message = self.message_input.text().strip()
        if not message:
            return
        
        # Add to chat display
        self.add_message("You", message)
        self.message_input.clear()
    
    def add_message(self, sender, message):
        """Add message to chat display"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        format = cursor.charFormat()
        format.setForeground(QColor("#0d47a1" if self.theme == "dark" else "#2196F3"))
        format.setFontWeight(QFont.Bold)
        
        cursor.setCharFormat(format)
        cursor.insertText(f"{sender}: ")
        
        format.setForeground(QColor("#ffffff" if self.theme == "dark" else "#000000"))
        format.setFontWeight(QFont.Normal)
        cursor.setCharFormat(format)
        cursor.insertText(f"{message}\n")
        
        self.chat_display.setTextCursor(cursor)
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)


# ============================================================================
# GROUP CHAT DIALOG
# ============================================================================

class GroupChatDialog(QDialog):
    """Group chat with multiple friends"""
    
    def __init__(self, parent=None, theme='dark', available_friends=None):
        super().__init__(parent)
        self.theme = theme
        self.available_friends = available_friends or {}
        self.selected_friends = []
        self.setWindowTitle("LibreSilent - Create Group Chat")
        self.setGeometry(100, 100, 600, 600)
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize group chat UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Create Group Chat")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Group name
        layout.addWidget(QLabel("Group Name:"))
        self.group_name_input = QLineEdit()
        self.group_name_input.setPlaceholderText("Enter group name...")
        layout.addWidget(self.group_name_input)
        
        layout.addSpacing(10)
        
        # Friends selection
        layout.addWidget(QLabel("Select Friends:"))
        
        self.friends_checkboxes = {}
        friends_scroll = QScrollArea()
        friends_widget = QWidget()
        friends_layout = QVBoxLayout()
        
        for code, friend in self.available_friends.items():
            checkbox = QCheckBox(friend['name'])
            checkbox.friend_code = code
            self.friends_checkboxes[code] = checkbox
            friends_layout.addWidget(checkbox)
        
        friends_layout.addStretch()
        friends_widget.setLayout(friends_layout)
        friends_scroll.setWidget(friends_widget)
        layout.addWidget(friends_scroll, 1)
        
        # Encryption option
        enc_layout = QHBoxLayout()
        enc_layout.addWidget(QLabel("Auto-negotiate Encryption:"))
        self.auto_encrypt_check = QCheckBox()
        self.auto_encrypt_check.setChecked(True)
        enc_layout.addWidget(self.auto_encrypt_check)
        enc_layout.addStretch()
        layout.addLayout(enc_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        create_btn = QPushButton("Create Group")
        create_btn.clicked.connect(self.create_group)
        btn_layout.addWidget(create_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
    
    def create_group(self):
        """Create group chat with selected friends"""
        name = self.group_name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Warning", "Please enter a group name.")
            return
        
        # Get selected friends
        self.selected_friends = [code for code, checkbox in self.friends_checkboxes.items() if checkbox.isChecked()]
        
        if not self.selected_friends:
            QMessageBox.warning(self, "Warning", "Please select at least one friend.")
            return
        
        if len(self.selected_friends) < 2:
            QMessageBox.warning(self, "Warning", "Group chat requires at least 2 friends.")
            return
        
        self.accept()
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)


# ============================================================================
# FRIENDS DIALOG
# ============================================================================

class FriendsDialog(QDialog):
    """Friends management dialog"""
    
    def __init__(self, parent=None, theme='dark'):
        super().__init__(parent)
        self.theme = theme
        self.setWindowTitle("LibreSilent - Friends")
        self.setGeometry(100, 100, 600, 500)
        self.friends = SettingsManager.load_friends()
        self.profile = SettingsManager.load_profile()
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize friends UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Friends & Profile")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Profile section
        profile_group = QWidget()
        profile_layout = QVBoxLayout()
        
        profile_label = QLabel("Your Profile")
        profile_label.setFont(QFont("Arial", 11, QFont.Bold))
        profile_layout.addWidget(profile_label)
        
        # Username
        profile_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setText(self.profile.get('username', ''))
        profile_layout.addWidget(self.username_input)
        
        # Friend Code
        profile_layout.addWidget(QLabel("Your Friend Code:"))
        code_layout = QHBoxLayout()
        self.friend_code_display = QLineEdit()
        self.friend_code_display.setReadOnly(True)
        self.friend_code_display.setText(self.profile.get('friend_code', ''))
        code_layout.addWidget(self.friend_code_display)
        
        generate_btn = QPushButton("Generate")
        generate_btn.setMaximumWidth(100)
        generate_btn.clicked.connect(self.generate_friend_code)
        code_layout.addWidget(generate_btn)
        
        profile_layout.addLayout(code_layout)
        profile_layout.addSpacing(15)
        
        # Your Activity section
        activity_label = QLabel("Your Activity")
        activity_label.setFont(QFont("Arial", 10, QFont.Bold))
        profile_layout.addWidget(activity_label)
        
        self.your_activity_display = QLabel("No activity being shared")
        self.your_activity_display.setStyleSheet("color: #888888; font-size: 9px;")
        self.your_activity_display.setWordWrap(True)
        profile_layout.addWidget(self.your_activity_display)
        
        profile_layout.addSpacing(10)
        
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        
        layout.addSpacing(15)
        
        # Friends section
        friends_label = QLabel("Friends List")
        friends_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(friends_label)
        
        # Friends list
        self.friends_list = QTextEdit()
        self.friends_list.setReadOnly(True)
        self.refresh_friends_list()
        layout.addWidget(self.friends_list, 1)
        
        # Friends buttons
        friends_btn_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Friend")
        add_btn.clicked.connect(self.add_friend)
        friends_btn_layout.addWidget(add_btn)
        
        delete_btn = QPushButton("Remove Friend")
        delete_btn.clicked.connect(self.remove_friend)
        friends_btn_layout.addWidget(delete_btn)
        
        dm_btn = QPushButton("Direct Message")
        dm_btn.clicked.connect(self.start_direct_message)
        friends_btn_layout.addWidget(dm_btn)
        
        layout.addLayout(friends_btn_layout)
        
        # Group chat button
        group_btn = QPushButton("Create Group Chat")
        group_btn.clicked.connect(self.create_group_chat)
        layout.addWidget(group_btn)
        
        # Close button
        close_layout = QHBoxLayout()
        close_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setMaximumWidth(100)
        close_btn.clicked.connect(self.accept)
        close_layout.addWidget(close_btn)
        layout.addLayout(close_layout)
        
        self.setLayout(layout)
        
        # Update your activity display after UI is initialized
        self.refresh_your_activity()

    def update_activity_display(self, activity):
        self.profile['current_activity'] = activity
        self.refresh_your_activity()
    
    def generate_friend_code(self):
        """Generate a new friend code"""
        friend_code = hashlib.sha256(f"{self.username_input.text()}{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:16].upper()
        self.friend_code_display.setText(friend_code)
        self.profile['friend_code'] = friend_code
        SettingsManager.save_profile(self.profile)
    
    def add_friend(self):
        """Add a new friend"""
        code, ok = QInputDialog.getText(self, "Add Friend", "Enter friend's code:")
        if not ok or not code:
            return
        
        name, ok = QInputDialog.getText(self, "Add Friend", "Enter friend's name:")
        if not ok or not name:
            return
        
        if code in self.friends:
            QMessageBox.warning(self, "Warning", "Friend already added.")
            return
        
        self.friends[code] = {
            'name': name,
            'code': code,
            'added_date': datetime.datetime.now().isoformat(),
            'online': False
        }
        
        SettingsManager.save_friends(self.friends)
        self.refresh_friends_list()
        QMessageBox.information(self, "Success", f"Added {name} as a friend!")
    
    def remove_friend(self):
        """Remove a friend"""
        if not self.friends:
            QMessageBox.warning(self, "Warning", "No friends to remove.")
            return
        
        friend_names = [f['name'] for f in self.friends.values()]
        name, ok = QInputDialog.getItem(self, "Remove Friend", "Select friend:", friend_names, 0, False)
        if not ok:
            return
        
        # Find and remove friend
        for code, friend in list(self.friends.items()):
            if friend['name'] == name:
                del self.friends[code]
                SettingsManager.save_friends(self.friends)
                self.refresh_friends_list()
                QMessageBox.information(self, "Success", f"Removed {name} from friends.")
                return
    
    def start_direct_message(self):
        """Start a direct message with a friend"""
        if not self.friends:
            QMessageBox.warning(self, "Warning", "No friends to message.")
            return
        
        friend_names = [f['name'] for f in self.friends.values()]
        friend_name, ok = QInputDialog.getItem(self, "Direct Message", "Select friend:", friend_names, 0, False)
        if not ok:
            return
        
        # Find the friend code for this friend
        friend_code = None
        for code, friend in self.friends.items():
            if friend['name'] == friend_name:
                friend_code = code
                break
        
        if friend_code:
            # Create and show direct message dialog
            dm_dialog = DirectMessageDialog(self, self.theme, friend_name, friend_code)
            dm_dialog.exec_()
    
    def create_group_chat(self):
        """Create a group chat with multiple friends"""
        if not self.friends:
            QMessageBox.warning(self, "Warning", "No friends to chat with.")
            return
        
        # Create and show group chat creation dialog
        group_dialog = GroupChatDialog(self, self.theme, self.friends)
        if group_dialog.exec_() == QDialog.Accepted:
            selected_friends = group_dialog.get_selected_friends()
            group_name = group_dialog.get_group_name()
            auto_encrypt = group_dialog.get_auto_encrypt()
            
            if selected_friends and group_name:
                # Create group chat entry
                import hashlib
                import time
                group_id = hashlib.sha256(f"{group_name}_{time.time()}".encode()).hexdigest()[:16]
                
                # Load existing chats
                chats = SettingsManager.load_chats()
                
                # Create new group chat entry
                chats[group_id] = {
                    'type': 'group',
                    'name': group_name,
                    'members': selected_friends,
                    'auto_encrypt': auto_encrypt,
                    'created': time.time(),
                    'messages': []
                }
                
                # Save chats
                SettingsManager.save_chats(chats)
                
                QMessageBox.information(self, "Success", f"Group chat '{group_name}' created with {len(selected_friends)} friends!")
    
    def refresh_friends_list(self):
        """Refresh the friends list display"""
        text = ""
        for code, friend in self.friends.items():
            status = "🟢 Online" if friend.get('online', False) else "⚪ Offline"
            text += f"• {friend['name']}\n  Code: {code}\n  Status: {status}"
            
            # Add activity information if available
            if friend.get('current_activity'):
                activity = friend.get('current_activity', {})
                source = activity.get('source', 'Unknown')
                title = activity.get('title', 'N/A')
                artist = activity.get('artist', '')
                status_activity = activity.get('status', '')
                
                text += f"\n  Activity: 🎵 {source} - {title}"
                if artist:
                    text += f" ({artist})"
                if status_activity:
                    text += f" [{status_activity}]"
            
            text += "\n\n"
        
        if not text:
            text = "No friends yet.\n\nClick 'Add Friend' to add someone!"
        
        self.friends_list.setText(text)
    
    def refresh_your_activity(self):
        """Refresh your activity display"""
        activity = self.profile.get('current_activity')
        
        if activity:
            source = activity.get('source', 'Unknown')
            title = activity.get('title', 'N/A')
            artist = activity.get('artist', '')
            status = activity.get('status', '')
            
            text = f"🎵 {source} - {title}"
            if artist:
                text += f" ({artist})"
            if status:
                text += f" [{status}]"
        else:
            text = "No activity being shared"
        
        self.your_activity_display.setText(text)
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)


# ============================================================================
# SETTINGS DIALOG
# ============================================================================

class SettingsDialog(QDialog):
    """Settings panel for managing connections and preferences"""
    
    def __init__(self, parent=None, theme='dark'):
        super().__init__(parent)
        self.theme = theme
        self.setWindowTitle("LibreSilent - Settings")
        self.setGeometry(100, 100, 700, 600)
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        """Initialize settings UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Settings")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Create tabs
        tabs = QTabWidget()
        
        # Saved Connections tab
        connections_tab = self.create_connections_tab()
        tabs.addTab(connections_tab, "Saved Connections")
        
        # Import/Export tab
        import_export_tab = self.create_import_export_tab()
        tabs.addTab(import_export_tab, "Import/Export")
        
        # Preferences tab
        preferences_tab = self.create_preferences_tab()
        tabs.addTab(preferences_tab, "Preferences")
        
        layout.addWidget(tabs)
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.save_and_close)
        close_button.setMaximumWidth(100)
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def create_connections_tab(self) -> QWidget:
        """Create saved connections management tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Connections list
        layout.addWidget(QLabel("Saved Connections:"))
        
        self.connections_list = QTextEdit()
        self.connections_list.setReadOnly(True)
        self.connections_list.setPlaceholderText("No saved connections yet.\n\nUse the buttons below to save or load connections.")
        layout.addWidget(self.connections_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        save_button = QPushButton("Save Current Connection")
        save_button.clicked.connect(self.save_connection)
        button_layout.addWidget(save_button)
        
        load_button = QPushButton("Load Connection")
        load_button.clicked.connect(self.load_connection)
        button_layout.addWidget(load_button)
        
        delete_button = QPushButton("Delete Selected")
        delete_button.clicked.connect(self.delete_connection)
        button_layout.addWidget(delete_button)
        
        layout.addLayout(button_layout)
        
        # Load saved connections list
        self.refresh_connections_list()
        
        tab.setLayout(layout)
        return tab
    
    def create_import_export_tab(self) -> QWidget:
        """Create import/export settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Export section
        export_group_layout = QVBoxLayout()
        export_label = QLabel("Export Settings")
        export_label.setFont(QFont("Arial", 11, QFont.Bold))
        export_group_layout.addWidget(export_label)
        
        export_info = QLabel("Export your encrypted connection settings to a file.")
        export_info.setStyleSheet("color: #888888; font-size: 10px;")
        export_group_layout.addWidget(export_info)
        
        export_button = QPushButton("Export Settings File")
        export_button.clicked.connect(self.export_settings)
        export_group_layout.addWidget(export_button)
        
        layout.addLayout(export_group_layout)
        layout.addSpacing(20)
        
        # Import section
        import_group_layout = QVBoxLayout()
        import_label = QLabel("Import Settings")
        import_label.setFont(QFont("Arial", 11, QFont.Bold))
        import_group_layout.addWidget(import_label)
        
        import_info = QLabel("Import encrypted connection settings from a file.")
        import_info.setStyleSheet("color: #888888; font-size: 10px;")
        import_group_layout.addWidget(import_info)
        
        import_button = QPushButton("Import Settings File")
        import_button.clicked.connect(self.import_settings)
        import_group_layout.addWidget(import_button)
        
        layout.addLayout(import_group_layout)
        layout.addStretch()
        
        tab.setLayout(layout)
        return tab
    
    def create_preferences_tab(self) -> QWidget:
        """Create preferences tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Display section
        display_label = QLabel("Display")
        display_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(display_label)
        
        self.show_timestamps_check = QCheckBox("Show message timestamps")
        self.show_timestamps_check.setChecked(True)
        layout.addWidget(self.show_timestamps_check)
        
        self.enable_animations_check = QCheckBox("Enable UI animations")
        self.enable_animations_check.setChecked(False)
        layout.addWidget(self.enable_animations_check)
        
        layout.addSpacing(20)
        
        # Notifications section
        notif_label = QLabel("Notifications")
        notif_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(notif_label)
        
        self.enable_notifications_check = QCheckBox("Enable desktop notifications")
        self.enable_notifications_check.setChecked(HAS_NOTIFICATIONS)
        layout.addWidget(self.enable_notifications_check)
        
        self.enable_notification_sounds_check = QCheckBox("Enable notification sounds")
        self.enable_notification_sounds_check.setChecked(True)
        layout.addWidget(self.enable_notification_sounds_check)
        
        layout.addSpacing(20)
        
        # Connection section
        connection_label = QLabel("Connection")
        connection_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(connection_label)
        
        self.auto_save_settings_check = QCheckBox("Auto-save connection settings")
        layout.addWidget(self.auto_save_settings_check)
        
        layout.addSpacing(10)
        save_info = QLabel("When checked, connection settings will be automatically saved after successful connection.")
        save_info.setStyleSheet("color: #888888; font-size: 9px;")
        save_info.setWordWrap(True)
        layout.addWidget(save_info)
        
        layout.addSpacing(20)
        
        # Friends section
        friends_label = QLabel("Friends")
        friends_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(friends_label)
        
        self.enable_friends_check = QCheckBox("Enable Friends Feature")
        self.enable_friends_check.setChecked(False)
        layout.addWidget(self.enable_friends_check)
        
        friends_info = QLabel(
            "Allow other users with friends enabled to see your online status and add you as a friend. "
            "The friends feature enables direct messages and group chats with optional automatic encryption "
            "negotiation using shared friend codes."
        )
        friends_info.setStyleSheet("color: #888888; font-size: 9px;")
        friends_info.setWordWrap(True)
        layout.addWidget(friends_info)
        
        # Activity sharing section
        activity_label = QLabel("Activity Sharing")
        activity_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(activity_label)
        
        self.enable_activity_sharing_check = QCheckBox("Share What I'm Listening To / Playing")
        self.enable_activity_sharing_check.setChecked(False)
        layout.addWidget(self.enable_activity_sharing_check)
        
        activity_info = QLabel(
            "When enabled with Friends feature, shows friends what you're listening to on Spotify "
            "or what game you're playing via Discord RPC. Requires Spotify and/or Discord applications to be running. "
            "Install pypresence and spotipy packages for full functionality."
        )
        activity_info.setStyleSheet("color: #888888; font-size: 9px;")
        activity_info.setWordWrap(True)
        layout.addWidget(activity_info)
        
        layout.addSpacing(20)
        
        # Window behavior section
        window_label = QLabel("Window Behavior")
        window_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(window_label)
        
        self.close_to_tray_check = QCheckBox("Close to tray instead of exiting")
        self.close_to_tray_check.setChecked(False)
        layout.addWidget(self.close_to_tray_check)
        
        close_tray_info = QLabel("When enabled, closing the window will minimize to the system tray instead of closing the application.")
        close_tray_info.setStyleSheet("color: #888888; font-size: 9px;")
        close_tray_info.setWordWrap(True)
        layout.addWidget(close_tray_info)
        
        layout.addStretch()
        
        tab.setLayout(layout)
        return tab
    
    def refresh_connections_list(self):
        """Refresh the connections list display"""
        config_dir = SettingsManager.CONFIG_DIR
        connections_text = ""
        
        try:
            if os.path.exists(config_dir):
                files = [f for f in os.listdir(config_dir) if f.endswith('.json') and f != 'settings.json']
                if files:
                    for filename in files:
                        filepath = os.path.join(config_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                data = json.load(f)
                                timestamp = data.get('timestamp', 'Unknown')
                                connections_text += f"• {filename}\n  Saved: {timestamp}\n\n"
                        except:
                            connections_text += f"• {filename} (corrupted)\n\n"
        except:
            pass
        
        if connections_text:
            self.connections_list.setText(connections_text)
        else:
            self.connections_list.setText("No saved connections yet.\n\nUse the buttons below to save or load connections.")
    
    def save_connection(self):
        """Save current connection to file"""
        if not hasattr(self.parent(), 'settings') or not self.parent().settings:
            QMessageBox.warning(self, "Warning", "No active connection to save. Connect first.")
            return
        
        name, ok = QInputDialog.getText(self, "Save Connection", "Connection name:")
        if not ok or not name:
            return
        
        try:
            settings = self.parent().settings.copy()
            SettingsManager.ensure_config_dir()
            
            filepath = os.path.join(SettingsManager.CONFIG_DIR, f"{name}.json")
            password, ok = QInputDialog.getText(self, "Encryption Password", "Enter password for this connection:", QLineEdit.Password)
            if not ok:
                return
            
            if SettingsManager.save_settings(settings, password, filepath):
                QMessageBox.information(self, "Success", f"Connection '{name}' saved successfully.")
                self.refresh_connections_list()
            else:
                QMessageBox.critical(self, "Error", "Failed to save connection.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error saving connection: {e}")
    
    def load_connection(self):
        """Load connection from file"""
        try:
            config_dir = SettingsManager.CONFIG_DIR
            if not os.path.exists(config_dir):
                QMessageBox.warning(self, "Warning", "No saved connections found.")
                return
            
            files = [f for f in os.listdir(config_dir) if f.endswith('.json') and f != 'settings.json']
            if not files:
                QMessageBox.warning(self, "Warning", "No saved connections found.")
                return
            
            name, ok = QInputDialog.getItem(self, "Load Connection", "Select connection:", 
                                           [f.replace('.json', '') for f in files], 0, False)
            if not ok:
                return
            
            password, ok = QInputDialog.getText(self, "Encryption Password", "Enter password for this connection:", QLineEdit.Password)
            if not ok:
                return
            
            filepath = os.path.join(config_dir, f"{name}.json")
            settings = SettingsManager.load_settings(password, filepath)
            
            if settings:
                self.parent().settings = settings
                QMessageBox.information(self, "Success", f"Connection '{name}' loaded. Use 'Connect' to establish connection.")
            else:
                QMessageBox.critical(self, "Error", "Failed to load connection. Check password.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading connection: {e}")
    
    def delete_connection(self):
        """Delete a saved connection"""
        try:
            config_dir = SettingsManager.CONFIG_DIR
            if not os.path.exists(config_dir):
                return
            
            files = [f for f in os.listdir(config_dir) if f.endswith('.json') and f != 'settings.json']
            if not files:
                QMessageBox.warning(self, "Warning", "No saved connections found.")
                return
            
            name, ok = QInputDialog.getItem(self, "Delete Connection", "Select connection to delete:", 
                                           [f.replace('.json', '') for f in files], 0, False)
            if not ok:
                return
            
            reply = QMessageBox.question(self, "Confirm Delete", f"Delete connection '{name}'?",
                                        QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                filepath = os.path.join(config_dir, f"{name}.json")
                os.remove(filepath)
                QMessageBox.information(self, "Success", "Connection deleted.")
                self.refresh_connections_list()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error deleting connection: {e}")
    
    def export_settings(self):
        """Export settings to file"""
        try:
            filepath, _ = QFileDialog.getSaveFileName(self, "Export Settings", "", "JSON Files (*.json)")
            if not filepath:
                return
            
            if not filepath.endswith('.json'):
                filepath += '.json'
            
            password, ok = QInputDialog.getText(self, "Encryption Password", "Enter password to encrypt export:", QLineEdit.Password)
            if not ok:
                return
            
            if not hasattr(self.parent(), 'settings') or not self.parent().settings:
                QMessageBox.warning(self, "Warning", "No active connection settings to export.")
                return
            
            if SettingsManager.save_settings(self.parent().settings, password, filepath):
                # Also save to config.yml in config directory
                friends = SettingsManager.load_friends()
                profile = SettingsManager.load_profile()
                chats = SettingsManager.load_chats()
                
                # Collect current preferences
                preferences = {
                    'theme': self.parent().theme,
                    'show_timestamps': self.show_timestamps_check.isChecked(),
                    'enable_animations': self.enable_animations_check.isChecked(),
                    'enable_notifications': self.enable_notifications_check.isChecked(),
                    'enable_notification_sounds': self.enable_notification_sounds_check.isChecked(),
                    'auto_save_settings': self.auto_save_settings_check.isChecked(),
                    'friends_enabled': self.enable_friends_check.isChecked(),
                    'close_to_tray': self.close_to_tray_check.isChecked(),
                    'activity_sharing_enabled': self.enable_activity_sharing_check.isChecked(),
                }
                
                config_dict = SettingsManager.export_config_to_yaml(
                    self.parent().settings, friends, profile, chats, preferences
                )
                SettingsManager.save_config_yaml(config_dict)
                
                QMessageBox.information(self, "Success", 
                    f"Settings exported to {filepath}\n\nConfig also saved to config.yml")
            else:
                QMessageBox.critical(self, "Error", "Failed to export settings.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error exporting settings: {e}")
    
    def import_settings(self):
        """Import settings from file"""
        try:
            filepath, _ = QFileDialog.getOpenFileName(self, "Import Settings", "", "JSON Files (*.json)")
            if not filepath:
                return
            
            password, ok = QInputDialog.getText(self, "Encryption Password", "Enter password for imported settings:", QLineEdit.Password)
            if not ok:
                return
            
            settings = SettingsManager.load_settings(password, filepath)
            if settings:
                self.parent().settings = settings
                
                # Also update config.yml with imported settings
                friends = SettingsManager.load_friends()
                profile = SettingsManager.load_profile()
                chats = SettingsManager.load_chats()
                
                # Collect current preferences
                preferences = {
                    'theme': self.parent().theme,
                    'show_timestamps': self.show_timestamps_check.isChecked(),
                    'enable_animations': self.enable_animations_check.isChecked(),
                    'enable_notifications': self.enable_notifications_check.isChecked(),
                    'enable_notification_sounds': self.enable_notification_sounds_check.isChecked(),
                    'auto_save_settings': self.auto_save_settings_check.isChecked(),
                    'friends_enabled': self.enable_friends_check.isChecked(),
                    'close_to_tray': self.close_to_tray_check.isChecked(),
                    'activity_sharing_enabled': self.enable_activity_sharing_check.isChecked(),
                }
                
                config_dict = SettingsManager.export_config_to_yaml(settings, friends, profile, chats, preferences)
                SettingsManager.save_config_yaml(config_dict)
                
                QMessageBox.information(self, "Success", 
                    "Settings imported successfully and saved to config.yml\n\nUse 'Connect' to establish connection.")
            else:
                QMessageBox.critical(self, "Error", "Failed to import settings. Check password and file format.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error importing settings: {e}")
    
    def save_and_close(self):
        """Save preferences to config.yml and close dialog"""
        try:
            # Update main window preferences
            main_window = self.parent()
            main_window.show_timestamps = self.show_timestamps_check.isChecked()
            main_window.animations_enabled = self.enable_animations_check.isChecked()
            main_window.notifications_enabled = self.enable_notifications_check.isChecked()
            main_window.notification_sounds_enabled = self.enable_notification_sounds_check.isChecked()
            main_window.auto_save_enabled = self.auto_save_settings_check.isChecked()
            main_window.friends_enabled = self.enable_friends_check.isChecked()
            main_window.close_to_tray = self.close_to_tray_check.isChecked()
            main_window.activity_sharing_enabled = self.enable_activity_sharing_check.isChecked()
            
            # Collect all preferences
            preferences = {
                'theme': main_window.theme,
                'show_timestamps': main_window.show_timestamps,
                'enable_animations': main_window.animations_enabled,
                'enable_notifications': main_window.notifications_enabled,
                'enable_notification_sounds': main_window.notification_sounds_enabled,
                'auto_save_settings': main_window.auto_save_enabled,
                'friends_enabled': main_window.friends_enabled,
                'close_to_tray': main_window.close_to_tray,
                'activity_sharing_enabled': main_window.activity_sharing_enabled,
            }
            
            # Load other config sections and save
            friends = SettingsManager.load_friends()
            profile = SettingsManager.load_profile()
            chats = SettingsManager.load_chats()
            
            config_dict = SettingsManager.export_config_to_yaml(
                main_window.settings if main_window.settings else {}, 
                friends, profile, chats, preferences
            )
            SettingsManager.save_config_yaml(config_dict)
            
            self.accept()
        except Exception as e:
            print(f"Error saving preferences: {e}")
            self.accept()
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)


# ============================================================================
# MAIN APPLICATION WINDOW
# ============================================================================

class LibreSilentQt(QMainWindow):
    """Main application window for LibreSilent using Qt"""
    activity_changed = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LibreSilent - Encrypted IRC Client")
        self.setGeometry(100, 100, 1200, 800)
        
        # Theme
        self.theme = ThemeManager.detect_system_theme()
        
        # State variables
        self.irc_thread = None
        self.encryption_key = None
        self.channel = None
        self.nick = None
        self.is_ready_to_send = False
        self.settings = {}
        self.show_timestamps = True
        self.notifications_enabled = HAS_NOTIFICATIONS
        self.auto_save_enabled = False
        self.animations_enabled = False
        self.notification_sounds_enabled = True
        self.unread_count = 0
        self.has_unread = False
        self.friends_enabled = False
        self.close_to_tray = False
        self.activity_sharing_enabled = False
        self.activity_monitor = None
        
        # Load config.yml preferences
        self.load_config_preferences()
        
        # Initialize UI
        self.init_ui()
        self.apply_theme()
        
        # Setup system tray
        self.setup_tray()
        
        # Connect system tray
        if HAS_NOTIFICATIONS:
            if platform.system() == "Linux":
                notify2.init("LibreSilent")
            elif platform.system() == "Windows":
                self.toaster = ToastNotifier()
    
    def load_config_preferences(self):
        """Load preferences from config.yml on startup"""
        try:
            config = SettingsManager.load_config_yaml()
            if config:
                prefs = config.get('preferences', {})
                
                # Load theme preference
                theme_pref = prefs.get('theme', 'auto')
                if theme_pref != 'auto':
                    self.theme = theme_pref
                
                # Load UI preferences
                self.show_timestamps = prefs.get('show_timestamps', True)
                self.animations_enabled = prefs.get('enable_animations', False)
                self.notifications_enabled = prefs.get('enable_notifications', HAS_NOTIFICATIONS)
                self.notification_sounds_enabled = prefs.get('enable_notification_sounds', True)
                self.auto_save_enabled = prefs.get('auto_save_settings', False)
                self.friends_enabled = prefs.get('friends_enabled', False)
                self.close_to_tray = prefs.get('close_to_tray', False)
                self.activity_sharing_enabled = prefs.get('activity_sharing_enabled', False)
                
                print("Preferences loaded from config.yml")
        except Exception as e:
            print(f"Error loading config preferences: {e}")
    
    def init_ui(self):
        """Initialize main UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Main content
        content_layout = QHBoxLayout()
        
        # Chat area
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Monospace", 10))
        content_layout.addWidget(self.chat_display, 1)
        
        # Info panel (sidebar)
        info_panel = self.create_info_panel()
        content_layout.addWidget(info_panel, 0)
        
        main_layout.addLayout(content_layout, 1)
        
        # Input area
        input_area = self.create_input_area()
        main_layout.addWidget(input_area)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready to connect...")
        
        central_widget.setLayout(main_layout)
    
    def setup_tray(self):
        """Setup system tray icon and menu"""
        try:
            self.tray_icon = QSystemTrayIcon(self)
            self.tray_icon.setToolTip("LibreSilent - Encrypted IRC Client")
            
            # Create initial icon
            pixmap = QPixmap(64, 64)
            pixmap.fill(QColor(0, 0, 0, 0))
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setBrush(QColor("#0d47a1"))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(8, 8, 48, 48)
            painter.end()
            self.tray_icon.setIcon(QIcon(pixmap))
            
            # Create tray menu
            tray_menu = QMenu()
            
            show_action = tray_menu.addAction("Show")
            show_action.triggered.connect(self.show_from_tray)
            
            hide_action = tray_menu.addAction("Hide")
            hide_action.triggered.connect(self.hide_to_tray)
            
            tray_menu.addSeparator()
            
            # Only add close application option if close_to_tray is enabled
            if self.close_to_tray:
                close_app_action = tray_menu.addAction("Close Application")
                close_app_action.triggered.connect(self.close_application)
            else:
                quit_action = tray_menu.addAction("Quit")
                quit_action.triggered.connect(self.quit_app)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.tray_icon_activated)
            self.tray_icon.show()
        except Exception as e:
            print(f"Could not setup system tray: {e}")
            self.tray_icon = None
    
    def show_from_tray(self):
        """Show window from tray"""
        self.showNormal()
        self.activateWindow()
        self.has_unread = False
        self.unread_count = 0
        self.update_tray_icon()
    
    def hide_to_tray(self):
        """Hide window to tray"""
        self.hide()
        self.update_tray_icon()
    
    def tray_icon_activated(self, reason):
        """Handle tray icon activation"""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.isVisible():
                self.hide_to_tray()
            else:
                self.show_from_tray()
        elif reason == QSystemTrayIcon.Trigger:
            # Single click on some platforms
            if self.isVisible():
                self.hide_to_tray()
            else:
                self.show_from_tray()
    
    def update_tray_icon(self):
        """Update tray icon based on unread status"""
        if not hasattr(self, 'tray_icon') or self.tray_icon is None:
            return
        
        try:
            if self.has_unread and self.unread_count > 0:
                # Create icon with RED circle badge for unread messages
                pixmap = QPixmap(128, 128)
                pixmap.fill(QColor(0, 0, 0, 0))
                
                painter = QPainter(pixmap)
                painter.setRenderHint(QPainter.Antialiasing)
                
                # Draw RED circle for unread
                painter.setBrush(QColor("#E53935"))  # Red color
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(0, 0, 128, 128)
                
                # Draw number if < 10
                if self.unread_count <= 9:
                    painter.setPen(Qt.white)
                    font = QFont()
                    font.setPointSize(48)
                    font.setBold(True)
                    painter.setFont(font)
                    painter.drawText(QRect(0, 0, 128, 128), Qt.AlignCenter, str(self.unread_count))
                
                painter.end()
                self.tray_icon.setIcon(QIcon(pixmap))
            else:
                # Default icon - blue circle (no unread)
                pixmap = QPixmap(128, 128)
                pixmap.fill(QColor(0, 0, 0, 0))
                
                painter = QPainter(pixmap)
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setBrush(QColor("#0d47a1"))  # Blue color
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(10, 10, 108, 108)
                painter.end()
                
                self.tray_icon.setIcon(QIcon(pixmap))
        except:
            pass
    
    def quit_app(self):
        """Quit application"""
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.hide()
        self.close()
        QApplication.quit()
    
    def close_application(self):
        """Close application (when close_to_tray is enabled)"""
        if self.irc_thread:
            self.irc_thread.stop()
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.hide()
        QApplication.quit()
    
    def create_header(self) -> QFrame:
        """Create header with connection controls"""
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header_layout = QHBoxLayout()
        
        title = QLabel("LibreSilent")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Connection status indicator
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("color: red; font-size: 16px;")
        header_layout.addWidget(self.status_indicator)
        
        self.status_label = QLabel("Disconnected")
        header_layout.addWidget(self.status_label)
        
        header_layout.addSpacing(20)
        
        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.show_connection_dialog)
        header_layout.addWidget(self.connect_button)
        
        # Disconnect button
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.clicked.connect(self.disconnect)
        header_layout.addWidget(self.disconnect_button)
        
        header.setLayout(header_layout)
        return header
    
    def create_input_area(self) -> QFrame:
        """Create message input area"""
        input_frame = QFrame()
        input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here... (disabled until connected)")
        self.message_input.setEnabled(False)
        self.message_input.returnPressed.connect(self.send_message)
        input_layout.addWidget(self.message_input)
        
        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setMaximumWidth(100)
        input_layout.addWidget(self.send_button)
        
        input_frame.setLayout(input_layout)
        return input_frame
    
    def create_info_panel(self) -> QFrame:
        """Create info panel sidebar"""
        panel = QFrame()
        panel.setFrameShape(QFrame.StyledPanel)
        panel.setMaximumWidth(250)
        panel_layout = QVBoxLayout()
        
        # Title
        title = QLabel("Connection Info")
        title_font = QFont()
        title_font.setBold(True)
        title.setFont(title_font)
        panel_layout.addWidget(title)
        
        # Info labels
        panel_layout.addWidget(QLabel("Server:"))
        self.info_server = QLabel("—")
        panel_layout.addWidget(self.info_server)
        
        panel_layout.addWidget(QLabel("Channel:"))
        self.info_channel = QLabel("—")
        panel_layout.addWidget(self.info_channel)
        
        panel_layout.addWidget(QLabel("Nickname:"))
        self.info_nick = QLabel("—")
        panel_layout.addWidget(self.info_nick)
        
        panel_layout.addSpacing(20)
        
        # Security options
        security_title = QLabel("Security Options")
        security_title.setFont(title_font)
        panel_layout.addWidget(security_title)
        
        self.encrypt_names_toggle = QCheckBox("Encrypt Names")
        self.encrypt_names_toggle.setEnabled(False)
        panel_layout.addWidget(self.encrypt_names_toggle)
        
        self.double_encrypt_toggle = QCheckBox("Double Encryption")
        self.double_encrypt_toggle.setEnabled(False)
        panel_layout.addWidget(self.double_encrypt_toggle)
        
        self.rotation_toggle = QCheckBox("Code Rotation")
        self.rotation_toggle.setEnabled(False)
        panel_layout.addWidget(self.rotation_toggle)
        
        self.tor_toggle = QCheckBox("TOR Routing")
        self.tor_toggle.setEnabled(False)
        panel_layout.addWidget(self.tor_toggle)
        
        panel_layout.addSpacing(20)
        
        # Theme selector
        theme_title = QLabel("Theme")
        theme_title.setFont(title_font)
        panel_layout.addWidget(theme_title)
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System Default", "Light", "Dark"])
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        panel_layout.addWidget(self.theme_combo)
        
        panel_layout.addStretch()
        
        # Friends button
        friends_button = QPushButton("Friends")
        friends_button.clicked.connect(self.show_friends_dialog)
        panel_layout.addWidget(friends_button)
        
        # Settings button
        settings_button = QPushButton("Settings")
        settings_button.clicked.connect(self.show_settings)
        panel_layout.addWidget(settings_button)
        
        panel.setLayout(panel_layout)
        return panel
    
    def show_connection_dialog(self):
        """Show connection settings dialog"""
        dialog = ConnectionSettingsDialog(self, self.theme)
        
        # Animate dialog entrance
        if self.animations_enabled:
            self.animate_slide_in(dialog, direction="down", duration=300)
        
        if dialog.exec_() == QDialog.Accepted:
            self.settings = dialog.get_settings()
            self.connect_to_irc()
    
    def connect_to_irc(self):
        """Connect to IRC server"""
        try:
            server = self.settings['server']
            port = self.settings['port']
            nick = self.settings['nick']
            key = self.settings['key']
            
            if not all([server, port, nick, key]):
                QMessageBox.critical(self, "Error", "All connection fields are required.")
                return
            
            self.nick = nick
            self.encryption_key = derive_key(
                key,
                self.settings.get('rotation_key'),
                self.settings.get('use_rotation', False)
            )
            
            if self.settings['auto_channel']:
                channel_hash = hashlib.sha256(self.encryption_key).hexdigest()[:8]
                self.channel = f"#ls{channel_hash}"
            else:
                self.channel = self.settings['channel']
                if not self.channel.startswith('#'):
                    self.channel = f"#{self.channel}"
            
            # Update UI
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            self.create_loading_animation()
            self.status_indicator.setStyleSheet("color: orange; font-size: 16px;")
            self.status_bar.showMessage(f"Connecting to {server}:{port}...")
            
            # Update info panel
            self.info_server.setText(f"{server}:{port}")
            self.info_channel.setText(self.channel)
            self.info_nick.setText(nick)
            
            # Update toggles
            self.encrypt_names_toggle.setChecked(self.settings.get('encrypt_names', True))
            self.double_encrypt_toggle.setChecked(self.settings.get('double_encrypt', False))
            self.rotation_toggle.setChecked(self.settings.get('use_rotation', False))
            self.tor_toggle.setChecked(self.settings.get('use_tor', False))
            
            # Start IRC thread
            self.irc_thread = IRCHandler(
                server, port, nick, self.channel,
                use_tor=self.settings.get('use_tor', False),
                tor_port=self.settings.get('tor_port', 9050)
            )
            self.irc_thread.message_received.connect(self.on_message_received)
            self.irc_thread.system_message.connect(self.on_system_message)
            self.irc_thread.system_error.connect(self.on_system_error)
            self.irc_thread.connected.connect(self.on_connected)
            self.irc_thread.start()
            
            self.add_system_message(f"Connecting to {server}:{port}...")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Connection error: {e}")
            self.status_bar.showMessage("Connection failed")
    
    def disconnect(self):
        """Disconnect from IRC"""
        if self.irc_thread:
            self.irc_thread.stop()
            self.irc_thread = None
        
        self.stop_loading_animation()
        self.is_ready_to_send = False
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)
        
        self.status_indicator.setStyleSheet("color: red; font-size: 16px;")
        self.status_label.setText("Disconnected")
        self.status_bar.showMessage("Disconnected")
        
        self.add_system_message("Disconnected from server")
    
    def send_message(self):
        """Send encrypted message"""
        if not self.is_ready_to_send or not self.irc_thread:
            return
        
        message = self.message_input.text().strip()
        if not message:
            return
        
        if self.settings.get('double_encrypt'):
            encrypted = encrypt_message_double(message, self.encryption_key)
        else:
            encrypted = encrypt_message(message, self.encryption_key)
        
        self.irc_thread.send_privmsg(encrypted)
        
        # Animate send button
        if self.animations_enabled:
            self.animate_bounce(self.send_button, duration=200)
        
        # Display own message
        self.add_message(self.nick, message)
        self.message_input.clear()
    
    def on_message_received(self, sender, message):
        """Handle incoming message from IRC"""
        decrypted = decrypt_message(message, self.encryption_key)
        if not decrypted and self.settings.get('double_encrypt'):
            decrypted = decrypt_message_double(message, self.encryption_key)
        
        displayed_sender = sender
        if self.settings.get('encrypt_names') and sender != self.nick:
            try:
                decrypted_sender = decrypt_message(sender, self.encryption_key)
                if not decrypted_sender and self.settings.get('double_encrypt'):
                    decrypted_sender = decrypt_message_double(sender, self.encryption_key)
                if decrypted_sender:
                    displayed_sender = decrypted_sender
            except:
                pass
        
        if decrypted:
            self.add_message(displayed_sender, decrypted)
            
            # Track unread if window is hidden
            if not self.isVisible():
                self.has_unread = True
                self.unread_count += 1
                self.update_tray_icon()
            
            self.show_notification("New Message", f"Message from {displayed_sender}")
        else:
            self.add_system_message(f"<{sender}> [Unencrypted or corrupt message]")
    
    def on_system_message(self, message):
        """Handle system message from IRC"""
        self.add_system_message(message)
    
    def on_system_error(self, error):
        """Handle system error from IRC"""
        self.add_error_message(error)
        self.disconnect()
    
    def on_connected(self):
        """Handle successful channel join"""
        self.stop_loading_animation()
        self.add_system_message(f"Successfully joined {self.channel}")
        self.is_ready_to_send = True
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        
        # Animate status indicator
        if self.animations_enabled:
            self.animate_status_pulse()
        
        self.status_indicator.setStyleSheet("color: green; font-size: 16px;")
        self.status_label.setText("Connected")
        self.status_bar.showMessage(f"Connected to {self.channel}")
        
        # Animate message input slide in
        if self.animations_enabled:
            self.animate_slide_in(self.message_input, direction="up", duration=400)
            self.animate_bounce(self.send_button, duration=400)
        
        # Auto-save settings if enabled
        if self.auto_save_enabled:
            self.auto_save_connection()
    
    def add_message(self, sender, message):
        """Add chat message to display"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        # Add timestamp if enabled
        if self.show_timestamps:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            format = cursor.charFormat()
            format.setForeground(QColor("#666666" if self.theme == "dark" else "#999999"))
            format.setFontItalic(True)
            cursor.setCharFormat(format)
            cursor.insertText(f"[{timestamp}] ")
        
        format = cursor.charFormat()
        format.setForeground(QColor("#0d47a1" if self.theme == "dark" else "#2196F3"))
        format.setFontWeight(QFont.Bold)
        format.setFontItalic(False)
        
        cursor.setCharFormat(format)
        cursor.insertText(f"{sender}: ")
        
        format.setForeground(QColor("#ffffff" if self.theme == "dark" else "#000000"))
        format.setFontWeight(QFont.Normal)
        cursor.setCharFormat(format)
        cursor.insertText(f"{message}\n")
        
        self.chat_display.setTextCursor(cursor)
        
        # Animate chat display on new message
        if self.animations_enabled:
            self.animate_message_fadeIn()
    
    def add_system_message(self, message):
        """Add system message to display"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        format = cursor.charFormat()
        format.setForeground(QColor("#666666" if self.theme == "dark" else "#999999"))
        format.setFontItalic(True)
        
        cursor.setCharFormat(format)
        cursor.insertText(f"[SYSTEM] {message}\n")
        
        self.chat_display.setTextCursor(cursor)
    
    def add_error_message(self, message):
        """Add error message to display"""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        format = cursor.charFormat()
        format.setForeground(QColor("#ff6b6b" if self.theme == "dark" else "#f44336"))
        format.setFontWeight(QFont.Bold)
        
        cursor.setCharFormat(format)
        cursor.insertText(f"[ERROR] {message}\n")
        
        self.chat_display.setTextCursor(cursor)
    
    def show_notification(self, title, message):
        """Show system notification"""
        if not self.notifications_enabled or not HAS_NOTIFICATIONS:
            return
        
        try:
            if platform.system() == "Linux":
                notification = notify2.Notification(title, message)
                notification.show()
            elif platform.system() == "Darwin":
                os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
            elif platform.system() == "Windows":
                self.toaster.show_toast(title, message, duration=5, threaded=True)
        except:
            pass
        
        # Play notification sound if enabled
        self.play_notification_sound()
    
    def play_notification_sound(self):
        """Play notification sound if enabled"""
        if not self.notification_sounds_enabled:
            return
        
        try:
            if platform.system() == "Linux":
                # Use system notification sound
                os.system("paplay /usr/share/sounds/freedesktop/stereo/complete.oga 2>/dev/null &")
            elif platform.system() == "Darwin":
                # Use macOS system sound
                os.system("afplay /System/Library/Sounds/Glass.aiff 2>/dev/null &")
            elif platform.system() == "Windows":
                import winsound
                # Use Windows default notification sound
                winsound.Beep(1000, 200)
        except:
            pass
    
    def on_theme_changed(self, theme_name):
        """Handle theme change"""
        if theme_name == "Light":
            self.theme = "light"
        elif theme_name == "Dark":
            self.theme = "dark"
        else:
            self.theme = ThemeManager.detect_system_theme()
        
        self.apply_theme()
    
    def apply_theme(self):
        """Apply theme to application"""
        # Fade out
        if self.animations_enabled:
            self.animate_slide_out(self.chat_display, direction="left", duration=150)
        
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)
        
        # Fade in
        QTimer.singleShot(150, lambda: self.animate_slide_in(self.chat_display, direction="right", duration=150) if self.animations_enabled else None)
    
    def changeEvent(self, event):
        """Handle window state changes"""
        if event.type() == QEvent.WindowStateChange:
            if self.windowState() & Qt.WindowMinimized:
                self.hide()
                self.update_tray_icon()
                return
        super().changeEvent(event)
    
    def closeEvent(self, event):
        """Handle application close"""
        # If close_to_tray is enabled, minimize to tray instead of closing
        if self.close_to_tray:
            event.ignore()
            self.hide()
            self.update_tray_icon()
            return
        
        # Otherwise, perform actual close
        if self.irc_thread:
            self.irc_thread.stop()
        if hasattr(self, 'tray_icon') and self.tray_icon is not None:
            self.tray_icon.hide()
        event.accept()
    
    def show_friends_dialog(self):
        """Show friends dialog"""
        if not self.friends_enabled:
            QMessageBox.information(
                self,
                "Friends Disabled",
                "Friends feature is disabled.\n\nEnable it in Settings → Preferences → Friends"
            )
            return
        
        dialog = FriendsDialog(self, self.theme)
        self.activity_changed.connect(dialog.update_activity_display)
        dialog.finished.connect(lambda: self.activity_changed.disconnect(dialog.update_activity_display))
        dialog.exec_()
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self, self.theme)
        
        # Sync current preferences to dialog
        dialog.show_timestamps_check.setChecked(self.show_timestamps)
        dialog.enable_notifications_check.setChecked(self.notifications_enabled)
        dialog.auto_save_settings_check.setChecked(self.auto_save_enabled)
        dialog.enable_animations_check.setChecked(self.animations_enabled)
        dialog.enable_notification_sounds_check.setChecked(self.notification_sounds_enabled)
        dialog.enable_friends_check.setChecked(self.friends_enabled)
        dialog.enable_activity_sharing_check.setChecked(self.activity_sharing_enabled)
        
        if dialog.exec_() == QDialog.Accepted:
            # Apply preferences from dialog
            self.show_timestamps = dialog.show_timestamps_check.isChecked()
            self.notifications_enabled = dialog.enable_notifications_check.isChecked()
            self.auto_save_enabled = dialog.auto_save_settings_check.isChecked()
            self.animations_enabled = dialog.enable_animations_check.isChecked()
            self.notification_sounds_enabled = dialog.enable_notification_sounds_check.isChecked()
            self.friends_enabled = dialog.enable_friends_check.isChecked()
            self.activity_sharing_enabled = dialog.enable_activity_sharing_check.isChecked()
            
            # Start/stop activity monitor based on setting
            if self.activity_sharing_enabled and self.friends_enabled:
                self.start_activity_monitor()
            elif self.activity_monitor:
                self.stop_activity_monitor()
    
    def start_activity_monitor(self):
        """Start the activity monitoring thread"""
        if self.activity_monitor is not None:
            return  # Already running
        
        try:
            self.activity_monitor = ActivityMonitorThread(
                enable_discord=HAS_DISCORD_RPC,
                enable_spotify=HAS_SPOTIFY
            )
            self.activity_monitor.activity_updated.connect(self.on_activity_updated)
            self.activity_monitor.activity_cleared.connect(self.on_activity_cleared)
            self.activity_monitor.start()
            
            print("Activity monitor started")
            self.add_system_message("Activity sharing enabled")
        except Exception as e:
            print(f"Error starting activity monitor: {e}")
            self.activity_monitor = None
    
    def stop_activity_monitor(self):
        """Stop the activity monitoring thread"""
        if self.activity_monitor is None:
            return
        
        try:
            self.activity_monitor.stop()
            self.activity_monitor.wait(3000)  # Wait up to 3 seconds
            self.activity_monitor = None
            print("Activity monitor stopped")
            self.add_system_message("Activity sharing disabled")
        except Exception as e:
            print(f"Error stopping activity monitor: {e}")
    
    def on_activity_updated(self, activity: dict):
        """Handle activity update from monitor"""
        try:
            # Store current activity in profile
            profile = SettingsManager.load_profile()
            profile['current_activity'] = activity
            profile['activity_timestamp'] = datetime.datetime.now().isoformat()
            SettingsManager.save_profile(profile)

            self.activity_changed.emit(activity)
            
            # Optionally broadcast to friends (would require IRC/chat implementation)
            activity_str = f"{activity.get('source', 'Unknown')}: {activity.get('title', 'N/A')}"
            if activity.get('artist'):
                activity_str += f" by {activity.get('artist')}"
            
            print(f"Activity updated: {activity_str}")
        except Exception as e:
            print(f"Error handling activity update: {e}")
    
    def on_activity_cleared(self):
        """Handle activity cleared signal"""
        try:
            # Clear activity from profile
            profile = SettingsManager.load_profile()
            profile['current_activity'] = None
            SettingsManager.save_profile(profile)
            self.activity_changed.emit({})
            
            print("Activity cleared")
        except Exception as e:
            print(f"Error handling activity clear: {e}")
    
    def auto_save_connection(self):
        """Auto-save current connection settings"""
        try:
            SettingsManager.ensure_config_dir()
            # Use server name as default save name
            server_name = self.settings.get('server', 'connection').replace('.', '-')
            filepath = os.path.join(SettingsManager.CONFIG_DIR, f"auto_{server_name}.json")
            
            # Use a default password for auto-saved connections
            password = hashlib.sha256(self.settings.get('key', '').encode()).hexdigest()[:16]
            
            if SettingsManager.save_settings(self.settings, password, filepath):
                self.add_system_message("✓ Connection auto-saved")
            else:
                self.add_system_message("⚠ Failed to auto-save connection")
        except Exception as e:
            print(f"Error auto-saving connection: {e}")
    
    def animate_widget(self, widget, duration=300):
        """Animate a widget with a fade-in/scale effect"""
        if not self.animations_enabled:
            return
        
        try:
            # Create scale animation
            animation = QPropertyAnimation(widget, b"geometry")
            animation.setDuration(duration)
            animation.setEasingCurve(QEasingCurve.OutCubic)
            
            # Get current geometry
            current_geo = widget.geometry()
            
            # Start from center, slightly smaller
            center_x = current_geo.x() + current_geo.width() // 2
            center_y = current_geo.y() + current_geo.height() // 2
            start_width = int(current_geo.width() * 0.9)
            start_height = int(current_geo.height() * 0.9)
            start_x = center_x - start_width // 2
            start_y = center_y - start_height // 2
            
            animation.setStartValue(QRect(start_x, start_y, start_width, start_height))
            animation.setEndValue(current_geo)
            animation.start()
        except:
            pass
    
    def animate_button_hover(self, button):
        """Animate button on hover"""
        if not self.animations_enabled:
            return
        
        try:
            animation = QPropertyAnimation(button, b"geometry")
            animation.setDuration(150)
            animation.setEasingCurve(QEasingCurve.OutQuad)
            
            current_geo = button.geometry()
            # Slightly scale up on hover
            scaled_width = int(current_geo.width() * 1.05)
            scaled_height = int(current_geo.height() * 1.05)
            scaled_x = current_geo.x() - (scaled_width - current_geo.width()) // 2
            scaled_y = current_geo.y() - (scaled_height - current_geo.height()) // 2
            
            animation.setEndValue(QRect(scaled_x, scaled_y, scaled_width, scaled_height))
            animation.start()
        except:
            pass
    
    def animate_status_pulse(self):
        """Animate status indicator with pulse effect"""
        if not self.animations_enabled:
            return
        
        try:
            animation = QPropertyAnimation(self.status_indicator, b"geometry")
            animation.setDuration(600)
            animation.setEasingCurve(QEasingCurve.InOutQuad)
            
            current_geo = self.status_indicator.geometry()
            # Pulse: grow then shrink
            center_x = current_geo.x() + current_geo.width() // 2
            center_y = current_geo.y() + current_geo.height() // 2
            
            # Grow to 1.3x
            new_width = int(current_geo.width() * 1.3)
            new_height = int(current_geo.height() * 1.3)
            new_x = center_x - new_width // 2
            new_y = center_y - new_height // 2
            
            animation.setEndValue(QRect(new_x, new_y, new_width, new_height))
            animation.start()
            
            # Return to normal after animation
            QTimer.singleShot(600, lambda: self.status_indicator.setGeometry(current_geo))
        except:
            pass
    
    def animate_message_fadeIn(self):
        """Animate chat display on new message"""
        if not self.animations_enabled:
            return
        
        try:
            # Create a subtle scroll animation
            animation = QPropertyAnimation(self.chat_display, b"geometry")
            animation.setDuration(200)
            animation.setEasingCurve(QEasingCurve.OutQuad)
            animation.start()
        except:
            pass
    
    def animate_slide_in(self, widget, direction="left", duration=500):
        """Slide a widget in from specified direction"""
        if not self.animations_enabled:
            return
        
        try:
            animation = QPropertyAnimation(widget, b"geometry")
            animation.setDuration(duration)
            animation.setEasingCurve(QEasingCurve.OutCubic)
            
            current_geo = widget.geometry()
            
            if direction == "left":
                start_geo = QRect(current_geo.x() - current_geo.width(), current_geo.y(), 
                                 current_geo.width(), current_geo.height())
            elif direction == "right":
                start_geo = QRect(current_geo.x() + current_geo.width(), current_geo.y(), 
                                 current_geo.width(), current_geo.height())
            elif direction == "up":
                start_geo = QRect(current_geo.x(), current_geo.y() - current_geo.height(), 
                                 current_geo.width(), current_geo.height())
            elif direction == "down":
                start_geo = QRect(current_geo.x(), current_geo.y() + current_geo.height(), 
                                 current_geo.width(), current_geo.height())
            else:
                return
            
            animation.setStartValue(start_geo)
            animation.setEndValue(current_geo)
            animation.start()
        except:
            pass
    
    def animate_slide_out(self, widget, direction="left", duration=500):
        """Slide a widget out in specified direction"""
        if not self.animations_enabled:
            return
        
        try:
            animation = QPropertyAnimation(widget, b"geometry")
            animation.setDuration(duration)
            animation.setEasingCurve(QEasingCurve.InCubic)
            
            current_geo = widget.geometry()
            
            if direction == "left":
                end_geo = QRect(current_geo.x() - current_geo.width(), current_geo.y(), 
                               current_geo.width(), current_geo.height())
            elif direction == "right":
                end_geo = QRect(current_geo.x() + current_geo.width(), current_geo.y(), 
                               current_geo.width(), current_geo.height())
            elif direction == "up":
                end_geo = QRect(current_geo.x(), current_geo.y() - current_geo.height(), 
                               current_geo.width(), current_geo.height())
            elif direction == "down":
                end_geo = QRect(current_geo.x(), current_geo.y() + current_geo.height(), 
                               current_geo.width(), current_geo.height())
            else:
                return
            
            animation.setStartValue(current_geo)
            animation.setEndValue(end_geo)
            animation.start()
        except:
            pass
    
    def animate_rotate(self, widget, duration=1000, repeats=0):
        """Rotate a widget (good for loading spinners)"""
        if not self.animations_enabled:
            return None
        
        try:
            # Use a timer to continuously rotate
            angle = [0]
            
            def rotate_step():
                angle[0] = (angle[0] + 6) % 360
                # Apply rotation via stylesheet (limited support in PyQt5)
                # For now, use geometry changes for visual effect
                if widget.objectName() == "status_indicator":
                    # Create pulsing effect for status indicator
                    size = 16 + (abs(angle[0] - 180) // 30)
                    widget.setStyleSheet(f"color: green; font-size: {size}px;")
            
            self.rotation_timer = QTimer()
            self.rotation_timer.timeout.connect(rotate_step)
            self.rotation_timer.start(50)
            return self.rotation_timer
        except:
            return None
    
    def stop_rotate(self):
        """Stop rotation animation"""
        if hasattr(self, 'rotation_timer'):
            self.rotation_timer.stop()
    
    def animate_bounce(self, widget, duration=500):
        """Bounce animation for a widget"""
        if not self.animations_enabled:
            return
        
        try:
            animation = QPropertyAnimation(widget, b"geometry")
            animation.setDuration(duration)
            animation.setEasingCurve(QEasingCurve.OutBounce)
            
            current_geo = widget.geometry()
            # Bounce down then back up
            bounce_geo = QRect(current_geo.x(), current_geo.y() + 20, 
                              current_geo.width(), current_geo.height())
            
            animation.setEndValue(bounce_geo)
            animation.start()
            
            # Return to original
            QTimer.singleShot(duration, lambda: widget.setGeometry(current_geo))
        except:
            pass
    
    def create_loading_animation(self):
        """Create a loading spinner animation on status label"""
        if not self.animations_enabled:
            return
        
        self.loading_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.loading_index = [0]
        
        def update_loading():
            self.loading_index[0] = (self.loading_index[0] + 1) % len(self.loading_frames)
            self.status_label.setText(f"{self.loading_frames[self.loading_index[0]]} Connecting...")
        
        self.loading_timer = QTimer()
        self.loading_timer.timeout.connect(update_loading)
        self.loading_timer.start(100)
    
    def stop_loading_animation(self):
        """Stop the loading spinner"""
        if hasattr(self, 'loading_timer'):
            self.loading_timer.stop()
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.irc_thread:
            self.irc_thread.stop()
        event.accept()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    app = QApplication(sys.argv)
    
    # Try to acquire single instance lock
    lock = SingleInstanceLock("libresilent")
    if not lock.acquire():
        QMessageBox.critical(
            None,
            "LibreSilent Already Running",
            "Another instance of LibreSilent is already running.\n\n"
            "Only one instance is allowed at a time."
        )
        sys.exit(1)
    
    window = LibreSilentQt()
    window.instance_lock = lock  # Keep reference to lock
    window.show()
    
    exit_code = app.exec_()
    lock.release()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
