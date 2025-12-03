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
from cryptography.fernet import Fernet, InvalidToken
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
# ENCRYPTION & KEY DERIVATION
# ============================================================================

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
        close_button.clicked.connect(self.accept)
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
        
        layout.addSpacing(20)
        
        # Notifications section
        notif_label = QLabel("Notifications")
        notif_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(notif_label)
        
        self.enable_notifications_check = QCheckBox("Enable desktop notifications")
        self.enable_notifications_check.setChecked(HAS_NOTIFICATIONS)
        self.enable_notifications_check.setEnabled(HAS_NOTIFICATIONS)
        layout.addWidget(self.enable_notifications_check)
        
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
                QMessageBox.information(self, "Success", f"Settings exported to {filepath}")
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
                QMessageBox.information(self, "Success", "Settings imported successfully. Use 'Connect' to establish connection.")
            else:
                QMessageBox.critical(self, "Error", "Failed to import settings. Check password and file format.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error importing settings: {e}")
    
    def apply_theme(self):
        """Apply theme to dialog"""
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)


# ============================================================================
# MAIN APPLICATION WINDOW
# ============================================================================

class LibreSilentQt(QMainWindow):
    """Main application window for LibreSilent using Qt"""
    
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
        
        # Initialize UI
        self.init_ui()
        self.apply_theme()
        
        # Connect system tray
        if HAS_NOTIFICATIONS:
            if platform.system() == "Linux":
                notify2.init("LibreSilent")
            elif platform.system() == "Windows":
                self.toaster = ToastNotifier()
    
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
        
        # Settings button
        settings_button = QPushButton("Settings")
        settings_button.clicked.connect(self.show_settings)
        panel_layout.addWidget(settings_button)
        
        panel.setLayout(panel_layout)
        return panel
    
    def show_connection_dialog(self):
        """Show connection settings dialog"""
        dialog = ConnectionSettingsDialog(self, self.theme)
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
            self.status_label.setText("Connecting...")
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
        self.add_system_message(f"Successfully joined {self.channel}")
        self.is_ready_to_send = True
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        
        self.status_indicator.setStyleSheet("color: green; font-size: 16px;")
        self.status_label.setText("Connected")
        self.status_bar.showMessage(f"Connected to {self.channel}")
        
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
        stylesheet = ThemeManager.get_stylesheet(self.theme)
        self.setStyleSheet(stylesheet)
    
    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self, self.theme)
        
        # Sync current preferences to dialog
        dialog.show_timestamps_check.setChecked(self.show_timestamps)
        dialog.enable_notifications_check.setChecked(self.notifications_enabled)
        dialog.auto_save_settings_check.setChecked(self.auto_save_enabled)
        
        if dialog.exec_() == QDialog.Accepted:
            # Apply preferences from dialog
            self.show_timestamps = dialog.show_timestamps_check.isChecked()
            self.notifications_enabled = dialog.enable_notifications_check.isChecked()
            self.auto_save_enabled = dialog.auto_save_settings_check.isChecked()
    
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
    window = LibreSilentQt()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
