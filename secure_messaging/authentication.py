# authentication.py
import hashlib
import secrets
import sqlite3
import re
from datetime import datetime
import logging  
from .logging_manager import global_logger

class SecurityException(Exception):
    pass
class UserAuthentication:
    def __init__(self, db_path='users.db'):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_tables()
        self._upgrade_database() 
        self.activity_log = []

    def _create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                salt TEXT,
                registration_date TEXT,
                last_login TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                activity_type TEXT,
                timestamp TEXT,
                details TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                username TEXT,
                timestamp TEXT,
                details TEXT
            )
        ''')
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_attempts (
            username TEXT PRIMARY KEY,
            failures INTEGER DEFAULT 0,
            last_attempt TEXT
        )
    ''')
        
        self.conn.commit()

    def get_user_auth(self, username: str) -> dict:
        self.cursor.execute('''
            SELECT password_hash FROM users WHERE username = ?
        ''', (username,))
        result = self.cursor.fetchone()
        return {'password_hash': result[0]} if result else None
    
    def _hash_password(self, password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()

    def _generate_salt(self) -> str:
        return secrets.token_hex(16)

    def _validate_password(self, password: str) -> bool:
        return (
            len(password) >= 8 and
            re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and
            re.search(r'\d', password) and
            re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        )

    def _log_activity(self, username: str, activity_type: str, details: str = ""):
        timestamp = datetime.now().isoformat()
        self.activity_log.append((username, activity_type, timestamp, details))
        self.cursor.execute('''
            INSERT INTO activity_logs (username, activity_type, timestamp, details)
            VALUES (?, ?, ?, ?)
        ''', (username, activity_type, timestamp, details))
        self.conn.commit()

    def log_security_event(self, event_type, username, details=""):
        try:
            timestamp = datetime.now().isoformat()
            self.cursor.execute('''
                INSERT INTO security_logs (username, event_type, timestamp, details)
                VALUES (?, ?, ?, ?)
            ''', (username, event_type, timestamp, details))
            self.conn.commit()
        except Exception as e:
            print(f"Failed to log security event: {e}")
            self.conn.rollback()
    
    def check_message_integrity(self, username, encrypted_data):
        is_tampered = False  
        if is_tampered:
            self.log_security_event("TAMPER_DETECTED", username, "Message integrity compromised")
        return is_tampered
    
    def register_user(self, username: str, password: str) -> bool:
        if not self._validate_password(password):
            self._log_activity(username, "REGISTER_FAIL", "Weak password")
            return False
        
        try:
            self.cursor.execute("PRAGMA table_info(users)")
            columns = {col[1] for col in self.cursor.fetchall()}
            required_columns = {'username', 'password_hash', 'salt'}
            if not required_columns.issubset(columns):
                raise sqlite3.DatabaseError("Invalid database schema version")
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            reg_date = datetime.now().isoformat()
            
            if 'registration_date' in columns and 'last_login' in columns:
                self.cursor.execute('''
                    INSERT INTO users (username, password_hash, salt, registration_date, last_login)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, password_hash, salt, reg_date, reg_date))
            else:
                self.cursor.execute('''
                    INSERT INTO users (username, password_hash, salt)
                    VALUES (?, ?, ?)
                ''', (username, password_hash, salt))
            
            self.conn.commit()
            self._log_activity(username, "REGISTER_SUCCESS")
            return True
        
        except sqlite3.IntegrityError:
            self._log_activity(username, "REGISTER_FAIL", "Username exists")
            return False
        
    def _upgrade_database(self):
        try:
            self.cursor.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in self.cursor.fetchall()]
            
            if 'registration_date' not in columns:
                self.cursor.execute('''
                    ALTER TABLE users ADD COLUMN registration_date TEXT
                ''')
            
            if 'last_login' not in columns:
                self.cursor.execute('''
                    ALTER TABLE users ADD COLUMN last_login TEXT
                ''')
                
            self.conn.commit()
        except Exception as e:
            print(f"Database upgrade error: {e}")
            self.conn.rollback()

    def authenticate_user(self, username: str, password: str) -> bool:
        try:
            if not username or not password:
                self._log_activity(username, "LOGIN_FAIL", "Empty credentials")
                return False

            self.cursor.execute('''
                SELECT password_hash, salt 
                FROM users 
                WHERE username = ?
            ''', (username,))
            user_data = self.cursor.fetchone()

            if not user_data:
                self._log_activity(username, "LOGIN_FAIL", "User not found")
                self.log_security_event("AUTH_FAILURE_USER_UNKNOWN", username)
                return False

            stored_hash, salt = user_data
            input_hash = self._hash_password(password, salt)

            if secrets.compare_digest(input_hash, stored_hash):
                last_login = datetime.now().isoformat()
                self.cursor.execute('''
                    UPDATE users 
                    SET last_login = ? 
                    WHERE username = ?
                ''', (last_login, username))
                self.conn.commit()
                self._log_activity(username, "LOGIN_SUCCESS")
                return True
            else:
                self._log_activity(username, "LOGIN_FAIL", "Incorrect password")
                self.log_security_event("AUTHENTICATION_FAILURE", username, "Authentication failed - incorrect password")
                
                global_logger.log_event('security', {
                    'username': username,
                    'event_type': 'AUTHENTICATION_FAILURE',
                    'status': 'failed',
                    'error_code': 'WRONG_PASSWORD',
                })
                
                try:
                    self.cursor.execute('''
                        INSERT OR REPLACE INTO auth_attempts 
                        (username, failures, last_attempt) 
                        VALUES (?, COALESCE(
                            (SELECT failures FROM auth_attempts WHERE username = ?), 0
                        ) + 1, ?)
                    ''', (username, username, datetime.now().isoformat()))
                    self.conn.commit()
                except sqlite3.OperationalError:
                    self.cursor.execute('''
                        CREATE TABLE IF NOT EXISTS auth_attempts (
                            username TEXT PRIMARY KEY,
                            failures INTEGER DEFAULT 0,
                            last_attempt TEXT
                        )
                    ''')
                    self.conn.commit()
                    self.cursor.execute('''
                        INSERT INTO auth_attempts (username, failures, last_attempt)
                        VALUES (?, 1, ?)
                    ''', (username, datetime.now().isoformat()))
                    self.conn.commit()
                
                return False
        except Exception as e:
            logging.error(f"Unexpected error during authentication for user {username}: {str(e)}")
            self.log_security_event("AUTH_UNEXPECTED_ERROR", username, str(e))
            return False

    def user_exists(self, username: str) -> bool:
        self.cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        return self.cursor.fetchone() is not None

    def close(self):
        self.conn.close()