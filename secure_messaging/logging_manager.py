# logging_manager.py
import json
from datetime import datetime, timezone 
import os
import hashlib
from .security_monitor import security_monitor
import logging
import warnings
warnings.filterwarnings("ignore")

monitor_logger = logging.getLogger('LoggingManager')
monitor_logger.setLevel(logging.WARNING)

class LoggingManager:
    def __init__(self, log_dir="ml_ready_logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        logging.getLogger('SecurityAlerts').setLevel(logging.WARNING)
        logging.getLogger('SecurityMonitor').setLevel(logging.WARNING)

    def _get_log_path(self, log_type: str) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"{log_type}_{date_str}.jsonl")

    def _create_ml_features(self, log_data: dict) -> dict:
        try:
            timestamp_str = log_data.get('timestamp')
            if timestamp_str:
                 timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                 if timestamp.tzinfo is None:
                      timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                 timestamp = datetime.now(timezone.utc) 
        except ValueError:
            monitor_logger.warning(f"Could not parse timestamp '{log_data.get('timestamp')}' in _create_ml_features, using current UTC time.")
            timestamp = datetime.now(timezone.utc)
        features = {
            'user_id': hashlib.sha256(log_data.get('username', 'unknown').encode()).hexdigest()[:8],
            'hour_of_day': timestamp.hour, 
            'day_of_week': timestamp.weekday(), 
            'minute_of_hour': timestamp.minute, 
            'event_category': log_data.get('event_type', '').split('_')[0].lower(),
            'event_action': '_'.join(log_data.get('event_type', '').split('_')[1:]).lower(),
            'success': 1 if log_data.get('status') == 'success' else 0,
            'attempt': 1 if log_data.get('status') == 'attempt' else 0,
            'encryption_used': 1 if log_data.get('encryption_status') == 'success' else 0,
            'integrity_verified': 1 if log_data.get('integrity_check') == 'passed' else 0,
            'message_length': log_data.get('message_length', 0),
            'file_size': log_data.get('file_size', 0),
            'error_occurred': 1 if 'error_code' in log_data else 0,
            'error_type': log_data.get('error_code', 'none'),
            'is_file_operation': 1 if 'file' in log_data.get('event_type', '').lower() else 0,
            'is_message_operation': 1 if 'message' in log_data.get('event_type', '').lower() else 0,
            'is_send_operation': 1 if 'send' in log_data.get('event_type', '').lower() else 0,
            'is_receive_operation': 1 if 'receive' in log_data.get('event_type', '').lower() else 0,
            'failures_last_hour': 0, 
            'previous_failures_this_hour': 0, 
            'is_after_hours': 1 if not (8 <= timestamp.hour <= 17) else 0, 
            'session_duration': 0, 
            'requests_last_5min': 0, 
            'recipient_id': 'none',
            'action': log_data.get('action', 'none')
        }

        if 'recipient' in log_data:
            features['recipient_id'] = hashlib.sha256(log_data['recipient'].encode()).hexdigest()[:8]

        return features

    def log_event(self, log_type: str, log_data: dict):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
        log_data.setdefault('timestamp', datetime.now(timezone.utc).isoformat())
        username = log_data.get('username', 'unknown')

        try:
            ml_entry = {
                'raw_log': log_data,
                'ml_features': self._create_ml_features(log_data),
            }
            allow_operation = security_monitor.check_security(ml_entry)
            log_path = self._get_log_path(log_type)
            with open(log_path, 'a') as f:
                f.write(json.dumps(ml_entry) + '\n')

        except Exception as e:
            monitor_logger.exception(f"Failed to process or log event for user {username}. Error: {e}")

global_logger = LoggingManager()