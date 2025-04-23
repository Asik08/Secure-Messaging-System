# security_monitor.py
import json
import os
from datetime import datetime, timedelta, timezone
from .security_model import SecurityLogAnalyzer 
import hashlib
import logging
from collections import defaultdict
import secrets
import warnings
warnings.filterwarnings("ignore")
monitor_logger = logging.getLogger('SecurityMonitor')
monitor_logger.setLevel(logging.INFO)
if not monitor_logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    monitor_logger.addHandler(handler)
    monitor_logger.propagate = False

BRUTE_FORCE_THRESHOLD = 5  # Attempts needed to trigger
BRUTE_FORCE_WINDOW = timedelta(minutes=5)
LOCKOUT_DURATION = timedelta(minutes=15) 

class SecurityMonitor:
    def __init__(self):
        self.brute_force_threshold = BRUTE_FORCE_THRESHOLD
        self.brute_force_window = BRUTE_FORCE_WINDOW
        self.lockout_duration = LOCKOUT_DURATION

        # --- ML Model Initialization 
        self.analyzer = SecurityLogAnalyzer()
        self.analyzer.models_ready = False
        if not self.analyzer.load_models():
            monitor_logger.warning("ML security models failed to load. Relying on rule-based checks.")
        # raise RuntimeError("Security models failed to initialize")
        else:
            monitor_logger.info("ML Security models loaded.")

        self.threat_history = [] # Keep for general threat logging
        self.security_log_dir = "security_logs"
        self.threat_log_file = os.path.join(self.security_log_dir, "threats.jsonl")
        self.admin_threat_log_file = os.path.join(self.security_log_dir, "admin_threats.jsonl")
        os.makedirs(self.security_log_dir, exist_ok=True)
        self.auth_failures = defaultdict(list) 
        self.locked_accounts = {}              
        monitor_logger.info("Security monitoring system initialized")

        # Admin credentials 
        self.admin_credentials = {
            "username": "admin",
            "salt": "secure_salt_123",
            "password_hash": hashlib.pbkdf2_hmac(
                'sha256',
                'admin123'.encode(),
                'secure_salt_123'.encode(),
                100000
            ).hex()
        }

    def _parse_log_timestamp(self, log_entry):
        try:
            # First check raw_log then ml_features
            iso_timestamp = (log_entry.get('raw_log', {}).get('timestamp') or 
                            log_entry.get('ml_features', {}).get('timestamp'))
            
            if iso_timestamp:
                dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            
            # If no timestamp found anywhere
            monitor_logger.debug("No timestamp in log entry, using current UTC")
            return datetime.now(timezone.utc)
            
        except Exception as e:
            monitor_logger.warning(f"Timestamp parse error: {e}, using current UTC")
            return datetime.now(timezone.utc)


    def _detect_brute_force(self, username: str, timestamp: datetime) -> bool:
        if timestamp.tzinfo is None:
            monitor_logger.warning("Received naive timestamp in _detect_brute_force, converting to UTC.")
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc) # Ensure it's UTC

        current_failures = self.auth_failures.get(username, [])
        relevant_failures = []
        for t in current_failures:
            if t.tzinfo is None: 
                t_aware = t.replace(tzinfo=timezone.utc)
            else:
                t_aware = t.astimezone(timezone.utc)

            if timestamp - t_aware <= self.brute_force_window:
                relevant_failures.append(t_aware) 

        self.auth_failures[username] = relevant_failures 

        failure_count = len(relevant_failures)
        monitor_logger.debug(f"Checking brute force for {username}. Failures in window: {failure_count}")

        if failure_count >= self.brute_force_threshold:
            current_aware_time = datetime.now(timezone.utc)
            if username in self.locked_accounts and current_aware_time < self.locked_accounts[username]:
                monitor_logger.info(f"User {username} is already locked out. Lockout active until {self.locked_accounts[username].isoformat()}.")
                return True 

            unlock_time = timestamp + self.lockout_duration
            self.locked_accounts[username] = unlock_time 
            monitor_logger.warning(f"BRUTE FORCE DETECTED for user '{username}'. Account locked until {unlock_time.isoformat()}. Failures: {failure_count}.")
            self._log_brute_force_attempt(username, timestamp, failure_count)
            return True 
        return False 

    def _classify_threat(self, features):
        if features.get('event_action') == 'self_send':
            return "SELF_SEND_VIOLATION"
        
        if features.get('integrity_verified', 1) == 0:
            return "INTEGRITY_COMPROMISED"

        if (features.get('is_after_hours', 0) == 1 and
            features.get('is_file_operation', 0) == 1 and
            features.get('event_action') == 'send' and
            (features.get('file_size', 0) > 100000 or features.get('recipient_id') == 'suspicious')):
            return "POTENTIAL_DATA_EXFILTRATION"

        if features.get('requests_last_5min', 0) > 75:
            return "HIGH_ACTIVITY_RATE"

        return "ML_DETECTED_ANOMALY"

    def _log_threat(self, threat_type, username, log_entry, detection_result, action_taken):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "threat_type": threat_type,
            "username": username,
            "event_type": log_entry.get('raw_log', {}).get('event_type', 'N/A'),
            "details": {
                "confidence": detection_result.get('classification_prob') if detection_result else None,
                "anomaly_score": detection_result.get('anomaly_score') if detection_result else None,
                "features": {k: v for k, v in log_entry.get('ml_features', {}).items()
                           if k in ['event_category', 'event_action', 'error_type', 'success', 'recipient_id', 'file_size', 'is_after_hours']}
            },
            "action_taken": action_taken
        }
        self.threat_history.append(entry)
        try:
            with open(self.threat_log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            if action_taken == "blocked_operation" or threat_type in ["BRUTE_FORCE_DETECTED", "INTEGRITY_FAILURE", "POTENTIAL_DATA_EXFILTRATION"]:
                with open(self.admin_threat_log_file, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            monitor_logger.info(f"Logged threat '{threat_type}' for user '{username}'. Action: {action_taken}")
        except Exception as e:
            monitor_logger.error(f"Failed to write threat log: {e}")

    def _log_brute_force_attempt(self, username: str, timestamp: datetime, failure_count: int):
        threat_entry = {
            "timestamp": timestamp.isoformat(),
            "specific_threat_type": "BRUTE_FORCE_DETECTED", 
            "username": username,
            "triggering_event_type": "AUTHENTICATION_FAILURE",
            "key_features": {
                "attempt_count_in_window": failure_count,
                "time_window_minutes": self.brute_force_window.total_seconds() / 60,
                "threshold": self.brute_force_threshold,
            },
            "action_taken": f"account_locked_for_{self.lockout_duration.total_seconds() / 60}_minutes",
        }
        try:
            # Log to both general and admin threat files
            with open(self.threat_log_file, 'a') as f:
                f.write(json.dumps(threat_entry) + '\n')
            with open(self.admin_threat_log_file, 'a') as f:
                f.write(json.dumps(threat_entry) + '\n')
            monitor_logger.info(f"Logged BRUTE_FORCE_DETECTED for {username} to threat files.")
        except Exception as e:
            monitor_logger.error(f"Failed to write brute force threat log: {e}")
    
    def is_admin(self, username: str, password: str) -> bool:
        if username != self.admin_credentials["username"]:
            return False
        try:
            input_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                self.admin_credentials["salt"].encode('utf-8'),
                100000
            ).hex()
            return secrets.compare_digest(input_hash, self.admin_credentials["password_hash"]) 
        except Exception as e:
            monitor_logger.error(f"Error during admin password hashing: {e}")
            return False
    
    def _log_self_send_attempt(self, username, log_entry):
        raw_log = log_entry.get('raw_log', {})
        event_type = raw_log.get('event_type', '').lower()
        if 'file' in event_type or raw_log.get('content_type') == 'file':
            content_type = "file"
        else:
            content_type = "message" 
        
        threat_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "specific_threat_type": "SELF_SEND_VIOLATION",
            "username": username,
            "triggering_event_type": raw_log.get('event_type', 'SELF_SEND_ATTEMPT'),
            "Key Indicators": {
                "error_code": raw_log.get('error_code', 'SELF_SEND')
            }
        }
        
        try:
            with open(self.admin_threat_log_file, 'a') as f:
                json.dump(threat_entry, f)
                f.write('\n')  
        except Exception as e:
            monitor_logger.error(f"Failed to log self-send attempt: {str(e)}")
        
    def check_security(self, log_entry) -> bool:
        raw_log = log_entry.get('raw_log', {})
        ml_features = log_entry.get('ml_features', {})
        username = raw_log.get('username', 'unknown')
        event_type = raw_log.get('event_type', 'unknown')
        status = raw_log.get('status', 'success')
        timestamp = self._parse_log_timestamp(log_entry)
        current_aware_time = datetime.now(timezone.utc)
        error_code = raw_log.get('error_code', '')
        action = raw_log.get('action', '')

        if event_type == 'AUTHENTICATION_FAILURE' and action == 'decrypt_file':
            monitor_logger.debug(f"Detected decrypt_file auth failure for {username}")
            self.auth_failures[username].append(timestamp)
            if self._detect_brute_force(username, timestamp):
                return False

        is_auth_attempt = (
            ml_features.get('event_category') == 'authentication' 
            or 'AUTHENTICATION' in event_type.upper()
            or raw_log.get('action') in ['decrypt_file', 'decrypt_message', 'send_message', 'send_file']  
            or event_type in ['FILE_DECRYPT', 'MESSAGE_DECRYPT']
        )
        
        if is_auth_attempt and username in self.locked_accounts:
            unlock_time = self.locked_accounts[username]
            if unlock_time.tzinfo is None:
                monitor_logger.error(f"Lockout time for {username} is naive. Fixing.")
                unlock_time = unlock_time.replace(tzinfo=timezone.utc)
                self.locked_accounts[username] = unlock_time

            if current_aware_time < unlock_time:
                monitor_logger.warning(f"Access denied for user '{username}'. Account locked until {unlock_time.isoformat()}.")
                self._log_threat("ACCESS_DENIED_LOCKED", username, log_entry, None, "blocked_operation (lockout)")
                return False
            else:
                monitor_logger.info(f"Lockout expired for user '{username}'. Removing lock.")
                del self.locked_accounts[username]
                if username in self.auth_failures:
                    del self.auth_failures[username]

        is_auth_failure = (
            (is_auth_attempt and (ml_features.get('success', 1) == 0 or status == 'failed' or 'FAILURE' in event_type.upper())) or
            (error_code in ['WRONG_PASSWORD', 'AUTHENTICATION_FAILED']) or
            (raw_log.get('event_type') == 'AUTHENTICATION_FAILURE' and raw_log.get('action') == 'decrypt_file')
        )
        
        if is_auth_failure:
            monitor_logger.debug(f"Processing authentication failure for user '{username}' at {timestamp.isoformat()}")
            self.auth_failures[username].append(timestamp)
            if self._detect_brute_force(username, timestamp):
                return False
        if (raw_log.get('event_type') == 'MESSAGE_DECRYPT_FAILURE' and 
            'INTEGRITY' in error_code):
            self._log_integrity_failure(username, log_entry)
            return False
        
        if event_type == 'SELF_SEND_ATTEMPT':
            self._log_self_send_attempt(username, log_entry)
            return False

        if status == 'failed' and any(code in error_code for code in ['INTEGRITY_FAILURE', 'HMAC_FAILURE', 'CHECKSUM']):
            if event_type != 'INTEGRITY_FAILURE':
                monitor_logger.warning(f"Confirmed integrity failure detected for user '{username}'.")
                self._log_integrity_failure(username, log_entry)
            return False 

        return True
       
    def _log_integrity_failure(self, username, log_entry):
        raw_log = log_entry.get('raw_log', {})
        ml_features = log_entry.get('ml_features', {})
        
        threat_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "specific_threat_type": "INTEGRITY_FAILURE",
            "username": username,
            "triggering_event_type": raw_log.get('event_type', 'MESSAGE_DECRYPT_FAILURE'),
            "key_features": {
                "error_code": raw_log.get('error_code', 'UNSPECIFIED_FAILURE'),
                "integrity_status": "failed",
                "operation_type": ml_features.get('event_category', 'unknown'),
                "message_length": ml_features.get('message_length', 0),
                "encryption_used": ml_features.get('encryption_used', 0),
                "ml_detected": False,
                "ml_confidence": None,
                "ml_anomaly_score": None
            }
        }

        if self.analyzer.models_ready:
            threat_entry["key_features"].update({
                "ml_detected": True,
                "ml_confidence": ml_features.get('classification_prob'),
                "ml_anomaly_score": ml_features.get('anomaly_score')
            })

        try:
            with open(self.admin_threat_log_file, 'a') as f:
                f.write(json.dumps(threat_entry) + '\n')
            monitor_logger.info(f"Logged INTEGRITY_FAILURE for {username} with full context.")
        except Exception as e:
            monitor_logger.error(f"Failed to write integrity log: {str(e)}")
    
security_monitor = SecurityMonitor()