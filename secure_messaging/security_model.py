import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    average_precision_score,
    roc_auc_score,
    recall_score 
)
import matplotlib.pyplot as plt
import joblib
import json
from datetime import datetime, timedelta
import random
from collections import deque, defaultdict
import time
import hashlib
import warnings
import logging
import os

warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')
warnings.filterwarnings("ignore", category=FutureWarning, module='sklearn')
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
alert_logger = logging.getLogger('SecurityAlerts')
alert_logger.setLevel(logging.INFO) 
alert_handler = logging.StreamHandler()
alert_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - ALERT - %(message)s'))
if not alert_logger.hasHandlers():
    alert_logger.addHandler(alert_handler)
alert_logger.propagate = False 

CLASSIFIER_THRESHOLD = 0.7 # Probability threshold for Random Forest
ANOMALY_THRESHOLD = -0.1   # Score threshold for Isolation Forest 
BRUTE_FORCE_THRESHOLD = 5  # Number of failures to trigger brute-force detection
TRAIN_FILE = 'synthetic_logs.jsonl'
TEST_FILE = 'test_logs.jsonl'
CLASSIFIER_MODEL_FILE = 'security_classifier.joblib'
ANOMALY_MODEL_FILE = 'anomaly_detector.joblib'

class SecurityLogAnalyzer:
    def __init__(self):
        self.numeric_features = [
            'hour_of_day', 'day_of_week', 'minute_of_hour',
            'message_length', 'file_size', 'attempt',
            'encryption_used', 'integrity_verified',
            'is_file_operation', 'is_message_operation',
            'is_send_operation', 'is_receive_operation',
            'failures_last_hour', 'previous_failures_this_hour', 
            'is_after_hours', 'success', 'error_occurred',
            'session_duration', 'requests_last_5min'
        ]
        self.categorical_features = [
            'event_category', 'event_action', 'error_type',
            'recipient_id', 'user_id'
        ]
        self.all_features = self.numeric_features + self.categorical_features
        self.target = 'is_anomaly'
        self.known_categories = {
            'event_category': ['message', 'file', 'authentication', 'system', 'unknown'],
            'event_action': ['send', 'upload', 'login', 'failure', 'download', 'execute', 'unknown'],
            'error_type': ['none', 'TIMEOUT', 'CONNECTION_FAILED',
                           'WRONG_PASSWORD', 'HMAC_FAILURE', 'PERMISSION_DENIED', 'unknown'],
            'recipient_id': ['none', 'internal', 'external', 'suspicious', 'unknown']
        }
        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), self.numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False),
                 self.categorical_features)
            ],
            remainder='drop' 
        )
        self.model = Pipeline(steps=[
            ('preprocessor', self.preprocessor),
            ('classifier', RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                class_weight='balanced',
                random_state=42,
                min_samples_leaf=5,
                max_features='sqrt',
                n_jobs=-1 
            ))
        ])
        self.anomaly_detector = Pipeline(steps=[
            ('preprocessor', self.preprocessor),
            ('detector', IsolationForest(
                n_estimators=200,
                contamination='auto',
                random_state=42,
                max_samples=0.8,
                n_jobs=-1 
            ))
        ])
        self.models_ready = False
        logging.info("SecurityLogAnalyzer initialized.")

    def _validate_input(self, df):
        df = df.copy()
        missing_cols = set(self.all_features) - set(df.columns)
        if missing_cols:
            logging.warning(f"Input data missing columns: {missing_cols}. Filling with defaults.")
            for col in missing_cols:
                if col in self.numeric_features:
                    df[col] = 0
                elif col in self.categorical_features:
                    df[col] = 'unknown' 
                else:
                    df[col] = 0

        extra_cols = set(df.columns) - set(self.all_features) - {self.target}
        if extra_cols:
            logging.warning(f"Input data has extra columns: {extra_cols}. They will be ignored.")
            keep_cols = self.all_features + ([self.target] if self.target in df.columns else [])
            df = df[keep_cols]

        for col in self.numeric_features:
            if col in df.columns:
                # Convert to numeric, coercing errors to NaN, then fill NaN with 0
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
                if not pd.api.types.is_float_dtype(df[col]):
                     df[col] = df[col].astype(float)

        for col in self.categorical_features:
            if col in df.columns:
                 # Convert to string, fill NaN with 'unknown'
                df[col] = df[col].astype(str).fillna('unknown')

        if self.target not in df.columns and 'is_anomaly' in df.columns: 
             df[self.target] = df['is_anomaly']
        elif self.target not in df.columns:
            logging.debug(f"Target column '{self.target}' not found. Assuming non-anomalous (0).")
            df[self.target] = 0 

        if self.target in df.columns:
             df[self.target] = pd.to_numeric(df[self.target], errors='coerce').fillna(0).astype(int)
             df[self.target] = df[self.target].apply(lambda x: 1 if x > 0 else 0) 

        ordered_cols = self.all_features + ([self.target] if self.target in df.columns else [])
        df = df[[col for col in ordered_cols if col in df.columns]]

        return df

    def load_data(self, filepath):
        try:
            with open(filepath, 'r') as f:
                data = []
                for i, line in enumerate(f):
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping malformed JSON line {i+1} in {filepath}")
        except FileNotFoundError:
            logging.error(f"Data file not found: {filepath}")
            return pd.DataFrame() 

        if not data:
            logging.error(f"No valid data loaded from {filepath}")
            return pd.DataFrame()

        ml_features_list = [x.get('ml_features', {}) for x in data]
        df = pd.DataFrame(ml_features_list)

        if df.empty:
             logging.error(f"DataFrame is empty after loading ml_features from {filepath}")
             return df

        df = self._validate_input(df)
        anomaly_conditions = (
            (df['error_occurred'] == 1) |
            (df['success'] == 0) |
            (df['hour_of_day'].between(0, 5)) | 
            (df['event_action'] == 'failure') |
            (df['recipient_id'] == 'suspicious') |
            (df['requests_last_5min'] > 50) |
            ((df['event_category'] == 'authentication') & (df['error_type'] == 'WRONG_PASSWORD')) |
            ((df['event_category'] == 'system') & (df['error_type'] == 'PERMISSION_DENIED')) |
            (df['integrity_verified'] == 0) 
        )
        df[self.target] = np.where(anomaly_conditions, 1, 0)
        return df

    def train(self, train_file):
        df = self.load_data(train_file)
        if df.empty or self.target not in df.columns:
            logging.error("Training data is empty or target column is missing. Cannot train.")
            return False

        # Check if there's enough data and variance
        if len(df) < 50:
             logging.error(f"Insufficient training data: {len(df)} rows found. Need at least 50.")
             return False
        if df[self.target].nunique() < 2:
             logging.warning(f"Training data only contains one class ({df[self.target].unique()}). Model might not generalize well.")

        X = df[self.all_features]
        y = df[self.target]

        logging.info("Training Classification Model (Random Forest)...")
        try:
            # Split data for evaluation during training
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            if X_train.empty or X_test.empty:
                 logging.error("Data split resulted in empty training or testing set.")
                 return False

            self.model.fit(X_train, y_train)

            # Evaluate on the test split
            y_pred = self.model.predict(X_test)
            y_proba = self.model.predict_proba(X_test)[:, 1]

            print("\n--- Classifier Training Evaluation ---")
            print(classification_report(y_test, y_pred))
            print("Confusion Matrix:")
            print(confusion_matrix(y_test, y_pred))
            try:
                roc_auc = roc_auc_score(y_test, y_proba)
                print(f"ROC AUC Score: {roc_auc:.4f}")
            except ValueError as e:
                 print(f"Could not calculate ROC AUC: {e}") 
            print("------------------------------------")

        except Exception as e:
            logging.error(f"Error training classifier: {e}", exc_info=True)
            return False

        logging.info("Training Anomaly Detection Model (Isolation Forest)...")
        try:
            self.anomaly_detector.fit(X)
        except Exception as e:
             logging.error(f"Error training anomaly detector: {e}", exc_info=True)

        try:
            joblib.dump(self.model, CLASSIFIER_MODEL_FILE)
            joblib.dump(self.anomaly_detector, ANOMALY_MODEL_FILE)
            logging.info(f"Models saved successfully to {CLASSIFIER_MODEL_FILE} and {ANOMALY_MODEL_FILE}.")
            self.models_ready = True
            return True
        except Exception as e:
            logging.error(f"Error saving models: {e}", exc_info=True)
            return False 

    def load_models(self):
         try:
              if os.path.exists(CLASSIFIER_MODEL_FILE) and os.path.exists(ANOMALY_MODEL_FILE):
                   self.model = joblib.load(CLASSIFIER_MODEL_FILE)
                   self.anomaly_detector = joblib.load(ANOMALY_MODEL_FILE)
                   self.models_ready = True
                   logging.info("Pre-trained models loaded successfully.")
                   return True
              else:
                   logging.warning("Model files not found. Please train the models first.")
                   self.models_ready = False
                   return False
         except Exception as e:
              logging.error(f"Error loading models: {e}", exc_info=True)
              self.models_ready = False
              return False

    def predict(self, log_entry_features):
        if not self.models_ready:
             logging.error("Models are not loaded or trained. Cannot predict.")
             return {'classification_prob': 0.0, 'anomaly_score': 0.0, 'is_malicious': False, 'error': 'Models not ready'}

        try:
            if isinstance(log_entry_features, dict):
                df = pd.DataFrame([log_entry_features])
            elif isinstance(log_entry_features, pd.DataFrame):
                df = log_entry_features.head(1) 
            else:
                 raise ValueError("Input must be a dictionary or DataFrame row")

            df = self._validate_input(df)
            if df.empty:
                raise ValueError("Input validation resulted in an empty DataFrame.")

            df_features = df[self.all_features]
            proba = self.model.predict_proba(df_features)[:, 1]
            anomaly_score = self.anomaly_detector.decision_function(df_features)

            is_malicious_flag = bool( 
                proba[0] > CLASSIFIER_THRESHOLD or anomaly_score[0] < ANOMALY_THRESHOLD
            )
            return {
                'classification_prob': float(proba[0]),
                'anomaly_score': float(anomaly_score[0]),
                'is_malicious': is_malicious_flag
            }
        except Exception as e:
            logging.error(f"Prediction error: {str(e)}", exc_info=True) 
            # Return a default non-malicious result with an error indicator
            return {
                'classification_prob': 0.0,
                'anomaly_score': 0.0, # Default anomaly score 
                'is_malicious': False,
                'error': str(e)
            }
class ActivitySimulator:
    """Generates synthetic normal and malicious security log activities."""
    def __init__(self):
        self.users = ['alice', 'bob', 'charlie', 'dave', 'eve'] # Include 'eve' as potential attacker
        self.normal_weights = [0.90, 0.08, 0.02] # Higher success rate for normal
        self.user_sessions = defaultdict(lambda: {'session_start': None, 'request_timestamps': deque(maxlen=100)}) 
        logging.info("ActivitySimulator initialized.")

    def _get_recent_requests(self, user, current_time, window_minutes=5):
        if user not in self.user_sessions or not self.user_sessions[user]['request_timestamps']:
            return 0
        cutoff_time = current_time - timedelta(minutes=window_minutes)
        count = sum(1 for ts in self.user_sessions[user]['request_timestamps'] if ts > cutoff_time)
        return count

    def generate_normal_activity(self, hours=24, start_time=None):
        logs = []
        base_time = start_time if start_time else datetime.now()
        logging.info(f"Generating {hours} hours of normal activity starting from {base_time}...")
        total_minutes = int(hours * 60)
        events_per_minute = 2 
        for minute_offset in range(total_minutes):
            current_minute_time = base_time + timedelta(minutes=minute_offset)
            num_events = np.random.poisson(events_per_minute) 
            for _ in range(num_events):
                timestamp = current_minute_time + timedelta(seconds=random.uniform(0, 59))
                user = random.choice(self.users)
                if self.user_sessions[user]['session_start'] is None:
                     self.user_sessions[user]['session_start'] = timestamp
                self.user_sessions[user]['request_timestamps'].append(timestamp)
                event_type = random.choices(
                    ['MESSAGE_SEND', 'FILE_UPLOAD', 'AUTHENTICATE', 'FILE_DOWNLOAD', 'SYSTEM_COMMAND'],
                    weights=[0.5, 0.20, 0.1, 0.15, 0.05] # Adjusted weights
                )[0]

                status = random.choices(
                    ['success', 'failure', 'error'], 
                    weights=self.normal_weights # Use defined normal weights
                )[0]
                event_category = 'message' if 'MESSAGE' in event_type else \
                                'file' if 'FILE' in event_type else \
                                'system' if 'SYSTEM' in event_type else 'authentication'

                event_action = 'send' if 'SEND' in event_type else \
                             'upload' if 'UPLOAD' in event_type else \
                             'download' if 'DOWNLOAD' in event_type else \
                             'execute' if 'COMMAND' in event_type else 'login'
                if event_category == 'authentication':
                    event_action = 'login' if status == 'success' else 'failure'

                error_type = 'none' if status == 'success' else \
                            random.choice(['TIMEOUT', 'CONNECTION_FAILED', 'PERMISSION_DENIED', 'HMAC_FAILURE']) # More error variety

                recipient = 'internal' if status == 'success' and \
                            ('SEND' in event_type or 'UPLOAD' in event_type) else 'none'

                session_duration = (timestamp - self.user_sessions[user]['session_start']).total_seconds()
                requests_last_5min = self._get_recent_requests(user, timestamp)
                failures_last_hour = 0 
                previous_failures_this_hour = 0
                is_anomaly_flag = (
                    (status != 'success') or
                    (not (8 <= timestamp.hour <= 17)) or 
                    (event_action == 'failure') or
                    (recipient == 'suspicious') or 
                    (requests_last_5min > 50) or
                    (event_category == 'authentication' and error_type == 'WRONG_PASSWORD') or 
                    (event_category == 'system' and error_type == 'PERMISSION_DENIED')
                 )
                log = {
                    'raw_log': {
                        'username': user,
                        'event_type': f"{event_type}_{status.upper()}",
                        'timestamp': timestamp.isoformat(),
                        'status': status,
                        'error_code': error_type if status != 'success' else 'none' 
                    },
                    'ml_features': {
                        'user_id': hashlib.sha256(user.encode()).hexdigest()[:8],
                        'hour_of_day': timestamp.hour,
                        'day_of_week': timestamp.weekday(),
                        'minute_of_hour': timestamp.minute,
                        'event_category': event_category,
                        'event_action': event_action,
                        'success': int(status == 'success'),
                        'error_occurred': int(status != 'success'),
                        'error_type': error_type,
                        'message_length': random.randint(10, 1000) if 'MESSAGE' in event_type else 0,
                        'file_size': random.randint(1024, 10240) if 'FILE' in event_type else 0,
                        'attempt': random.randint(0, 1) if event_category == 'authentication' else 1,
                        'encryption_used': random.randint(0, 1) if 'SEND' in event_type or 'UPLOAD' in event_type else 0,
                        'integrity_verified': random.randint(0, 1) if status == 'success' and ('DOWNLOAD' in event_type or 'UPLOAD' in event_type) else 0,
                        'is_file_operation': int('FILE' in event_type),
                        'is_message_operation': int('MESSAGE' in event_type),
                        'is_send_operation': int('SEND' in event_type),
                        'is_receive_operation': int('DOWNLOAD' in event_type),
                        'failures_last_hour': failures_last_hour,
                        'previous_failures_this_hour': previous_failures_this_hour,
                        'is_after_hours': int(not (8 <= timestamp.hour <= 17)),
                        'recipient_id': recipient,
                        'session_duration': max(0, session_duration), 
                        'requests_last_5min': requests_last_5min,
                        'is_anomaly': int(is_anomaly_flag) 
                    }
                }
                logs.append(log)
                if random.random() < 0.01: 
                    self.user_sessions.pop(user, None)

        logging.info(f"Generated {len(logs)} normal log entries.")
        # Shuffle logs to mix user activity
        random.shuffle(logs)
        return logs

    def generate_malicious_activity(self, attack_type, start_time=None):
        base_time = start_time if start_time else datetime.now()
        attacker = 'eve' 
        logs = []
        logging.info(f"Generating malicious activity: {attack_type} starting around {base_time}...")

        if attack_type == 'brute_force':
            num_attempts = random.randint(15, 30) 
            for i in range(num_attempts):
                timestamp = base_time + timedelta(seconds=random.uniform(i*1.5, i*2.5))
                fail_count = i + 1
                log = {
                    'raw_log': {
                        'username': attacker,
                        'event_type': 'AUTHENTICATION_FAILURE',
                        'timestamp': timestamp.isoformat(),
                        'status': 'failure',
                        'error_code': 'WRONG_PASSWORD'
                    },
                    'ml_features': {
                        'user_id': hashlib.sha256(attacker.encode()).hexdigest()[:8],
                        'hour_of_day': timestamp.hour,
                        'day_of_week': timestamp.weekday(),
                        'minute_of_hour': timestamp.minute,
                        'event_category': 'authentication',
                        'event_action': 'failure', 
                        'success': 0,
                        'error_occurred': 1,
                        'error_type': 'WRONG_PASSWORD',
                        'message_length': 0, 'file_size': 0, 'attempt': 1,
                        'encryption_used': 0, 'integrity_verified': 0,
                        'is_file_operation': 0, 'is_message_operation': 0,
                        'is_send_operation': 0, 'is_receive_operation': 0,
                        'failures_last_hour': fail_count,
                        'previous_failures_this_hour': fail_count,
                        'is_after_hours': int(not (8 <= timestamp.hour <= 17)),
                        'recipient_id': 'none',
                        'session_duration': 0, 
                        'requests_last_5min': fail_count,
                        'is_anomaly': 1 
                    }
                }
                logs.append(log)

        elif attack_type == 'data_exfiltration':
            num_transfers = random.randint(2, 5)
            exfil_time = base_time.replace(hour=random.randint(1, 4), minute=random.randint(0, 59)) 
            for i in range(num_transfers):
                 timestamp = exfil_time + timedelta(minutes=i * random.uniform(3, 7))
                 file_sz = random.randint(50 * 1024, 500 * 1024) # Larger files
                 log = {
                    'raw_log': {
                        'username': attacker,
                        'event_type': 'FILE_SEND_SUCCESS',
                        'timestamp': timestamp.isoformat(),
                        'status': 'success',
                        'file_size': file_sz,
                        'recipient': 'suspicious_domain.com'
                    },
                    'ml_features': {
                        'user_id': hashlib.sha256(attacker.encode()).hexdigest()[:8],
                        'hour_of_day': timestamp.hour,
                        'day_of_week': timestamp.weekday(),
                        'minute_of_hour': timestamp.minute,
                        'event_category': 'file',
                        'event_action': 'send',
                        'success': 1, 
                        'error_occurred': 0,
                        'error_type': 'none',
                        'message_length': 0,
                        'file_size': file_sz,
                        'attempt': 1,
                        'encryption_used': random.randint(0, 1), 
                        'integrity_verified': 0, 
                        'is_file_operation': 1, 'is_message_operation': 0,
                        'is_send_operation': 1, 'is_receive_operation': 0,
                        'failures_last_hour': 0, 
                        'previous_failures_this_hour': 0,
                        'is_after_hours': 1,
                        'recipient_id': 'suspicious',
                        'session_duration': random.uniform(300, 1800), 
                        'requests_last_5min': i + 1, 
                        'is_anomaly': 1 
                    }
                }
                 logs.append(log)

        elif attack_type == 'privilege_escalation':
            num_attempts = random.randint(5, 10)
            escalation_time = base_time + timedelta(minutes=random.uniform(1, 10)) 
            for i in range(num_attempts):
                timestamp = escalation_time + timedelta(minutes=i * random.uniform(1, 5))
                fail_count = i + 1
                log = {
                    'raw_log': {
                        'username': attacker,
                        'event_type': 'SYSTEM_COMMAND_FAILURE',
                        'timestamp': timestamp.isoformat(),
                        'status': 'failure',
                        'command': 'sudo rm -rf /', 
                        'error_code': 'PERMISSION_DENIED'
                    },
                    'ml_features': {
                        'user_id': hashlib.sha256(attacker.encode()).hexdigest()[:8],
                        'hour_of_day': timestamp.hour,
                        'day_of_week': timestamp.weekday(),
                        'minute_of_hour': timestamp.minute,
                        'event_category': 'system',
                        'event_action': 'execute', 
                        'success': 0, 'error_occurred': 1,
                        'error_type': 'PERMISSION_DENIED',
                        'message_length': 0, 'file_size': 0, 'attempt': 1,
                        'encryption_used': 0, 'integrity_verified': 0,
                        'is_file_operation': 0, 'is_message_operation': 0,
                        'is_send_operation': 0, 'is_receive_operation': 0,
                        'failures_last_hour': fail_count, 
                        'previous_failures_this_hour': fail_count,
                        'is_after_hours': int(not (8 <= timestamp.hour <= 17)),
                        'recipient_id': 'none',
                        'session_duration': random.uniform(180, 900), 
                        'requests_last_5min': fail_count, 
                        'is_anomaly': 1 
                    }
                }
                logs.append(log)

        logging.info(f"Generated {len(logs)} malicious log entries for {attack_type}.")
        return logs

class RealTimeMonitor:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.activity_window = deque(maxlen=100) 
        self.user_behavior = defaultdict(lambda: {
            'last_seen': None,
            'login_failures': deque(maxlen=20), 
            'request_timestamps': deque(maxlen=100), 
            'total_failures_last_hour': 0, 
        })
        self.detected_attack_types = [] 
        logging.info("RealTimeMonitor initialized.")

    def _update_user_state(self, user, timestamp_dt, ml_features):
        state = self.user_behavior[user]
        state['last_seen'] = timestamp_dt
        state['request_timestamps'].append(timestamp_dt)
        if ml_features.get('event_category') == 'authentication' and ml_features.get('success') == 0:
            state['login_failures'].append(timestamp_dt)
        elif ml_features.get('error_occurred') == 1:
            pass
        one_hour_ago = timestamp_dt - timedelta(hours=1)
        five_minutes_ago = timestamp_dt - timedelta(minutes=5)
        failures_now = sum(1 for ts in state['login_failures'] if ts > one_hour_ago)
        state['total_failures_last_hour'] = failures_now
        requests_now = sum(1 for ts in state['request_timestamps'] if ts > five_minutes_ago)
        return {
            'failures_last_hour': failures_now,
            'previous_failures_this_hour': failures_now,
            'requests_last_5min': requests_now
        }

    def process_log(self, log_entry):
        try:
            if 'raw_log' not in log_entry or 'ml_features' not in log_entry:
                 logging.warning("Skipping log entry missing 'raw_log' or 'ml_features'.")
                 return None
            if 'username' not in log_entry['raw_log'] or 'timestamp' not in log_entry['raw_log']:
                 logging.warning("Skipping log entry missing 'username' or 'timestamp' in raw_log.")
                 return None

            user = log_entry['raw_log']['username']
            timestamp_iso = log_entry['raw_log']['timestamp']
            timestamp_dt = datetime.fromisoformat(timestamp_iso)
            ml_features = log_entry['ml_features']
            stateful_features = self._update_user_state(user, timestamp_dt, ml_features)
            ml_features['failures_last_hour'] = stateful_features['failures_last_hour']
            ml_features['previous_failures_this_hour'] = stateful_features['previous_failures_this_hour']
            ml_features['requests_last_5min'] = stateful_features['requests_last_5min']
            result = self.analyzer.predict(ml_features) 
            if 'error' in result:
                 logging.warning(f"Prediction failed for log entry: {result['error']}")
                 self.activity_window.append({'log': log_entry, 'prediction': result, 'timestamp': timestamp_dt})
                 return result 

            self.activity_window.append({'log': log_entry, 'prediction': result, 'timestamp': timestamp_dt})
            if result.get('is_malicious', False): 
                attack_type = self._detect_attack_type(log_entry['ml_features'], stateful_features) 
                self.detected_attack_types.append(attack_type)
                self._trigger_alert(log_entry, result, attack_type, stateful_features)
            return result 

        except Exception as e:
            logging.error(f"Error processing log: {e}", exc_info=True)
            return {
                'classification_prob': 0.0,
                'anomaly_score': 0.0,
                'is_malicious': False,
                'error': f"Processing error: {str(e)}"
            }

    def _detect_attack_type(self, features, state_features):
        failures_last_hr = state_features['failures_last_hour']
        requests_last_5m = state_features['requests_last_5min']

        if features.get('event_category') == 'authentication' and failures_last_hr >= BRUTE_FORCE_THRESHOLD:
             return 'brute_force'
        elif (features.get('event_category') == 'file' and
              features.get('event_action') == 'send' and
              features.get('recipient_id') == 'suspicious' and
              features.get('is_after_hours') == 1):
             return 'data_exfiltration'
        elif (features.get('event_category') == 'system' and
              features.get('error_type') == 'PERMISSION_DENIED' and
              failures_last_hr > 3): 
             return 'privilege_escalation'
        elif requests_last_5m > 75 :
             return 'activity_spike'
        else:
             return 'suspicious_activity'

    def _trigger_alert(self, log_entry, result, attack_type, state_features):
        try:
            user = log_entry.get('raw_log', {}).get('username', 'unknown_user')
            event = log_entry.get('raw_log', {}).get('event_type', 'unknown_event')
            timestamp = datetime.now().isoformat() 
            recent_activity_context = []
            items_to_show = min(3, len(self.activity_window))
            for item in list(self.activity_window)[-items_to_show:]:
                try:
                    simplified_log = {
                         'event': item['log'].get('raw_log', {}).get('event_type', 'N/A'),
                         'user': item['log'].get('raw_log', {}).get('username', 'N/A'),
                         'ts': item['log'].get('raw_log', {}).get('timestamp', 'N/A'),
                         'status': item['log'].get('raw_log', {}).get('status', 'N/A')
                    }
                    pred = item.get('prediction', {})
                    simplified_pred = {
                        'prob': f"{pred.get('classification_prob', 0.0):.3f}",
                        'score': f"{pred.get('anomaly_score', 0.0):.3f}",
                        'malicious': pred.get('is_malicious', False)
                    }
                    recent_activity_context.append({
                         'log_summary': simplified_log,
                         'prediction': simplified_pred
                         })
                except Exception as ctx_err:
                     logging.warning(f"Error formatting context item: {ctx_err}")
                     recent_activity_context.append({'error': 'Failed to format item'})

            user_stats_context = {
                'failures_last_hour': state_features.get('failures_last_hour', 'N/A'),
                'requests_last_5min': state_features.get('requests_last_5min', 'N/A'),
                'last_seen': self.user_behavior[user].get('last_seen', 'N/A').isoformat() if self.user_behavior[user].get('last_seen') else 'N/A'
            }

            alert_details = {
                'alert_timestamp': timestamp,
                'triggering_event': event,
                'user': user,
                'detected_attack_type': attack_type,
                'classifier_confidence': float(result['classification_prob']),
                'anomaly_score': float(result['anomaly_score']),
                'context': {
                    'recent_activity': recent_activity_context,
                    'user_stats': user_stats_context
                },
                'triggering_features': {
                    'category': log_entry['ml_features'].get('event_category', 'N/A'),
                    'action': log_entry['ml_features'].get('event_action', 'N/A'),
                    'error': log_entry['ml_features'].get('error_type', 'N/A'),
                    'success': log_entry['ml_features'].get('success', 'N/A'),
                    'after_hours': log_entry['ml_features'].get('is_after_hours', 'N/A'),
                    'recipient': log_entry['ml_features'].get('recipient_id', 'N/A'),
                }
            }
            alert_message = json.dumps(alert_details, indent=2, default=str) 
            alert_logger.info(f"{attack_type.upper()} detected involving user {user}.\nDetails:\n{alert_message}")

        except Exception as e:
            logging.error(f"Failed to trigger/format alert: {e}", exc_info=True)

    def print_attack_summary(self):
        print("\n--- Attack Detection Summary ---")
        if not self.detected_attack_types:
            print("No attacks detected during this monitoring session.")
            return

        attack_counts = defaultdict(int)
        for attack in self.detected_attack_types:
            attack_counts[attack] += 1

        print("Detected Attack Incidents:")
        for attack, count in sorted(attack_counts.items()): 
            print(f"- {attack.replace('_', ' ').title()}: {count} incidents")
        print("-----------------------------")

def evaluate_model(analyzer, test_file):
    """Loads test data, runs predictions, and evaluates model performance."""
    logging.info(f"Evaluating model performance using test file: {test_file}")
    test_df = analyzer.load_data(test_file)
    if test_df.empty or analyzer.target not in test_df.columns:
         logging.error("Test data is empty or target column missing. Cannot evaluate.")
         return

    y_true = []
    y_pred_flag = [] 
    y_proba_clf = [] 
    results = [] 
    for index, row in test_df.iterrows():
         features = row.to_dict()
         true_label = features.pop(analyzer.target, 0) 
         result = analyzer.predict(features)
         results.append(result) 
         y_true.append(true_label)
         y_pred_flag.append(1 if result.get('is_malicious', False) else 0)
         y_proba_clf.append(result.get('classification_prob', 0.0))

    print("\n--- Model Evaluation on Test Data ---")
    if not y_true:
         print("No true labels found for evaluation.")
         return
    print(classification_report(y_true, y_pred_flag, target_names=['Normal (0)', 'Malicious (1)']))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_true, y_pred_flag, labels=[0, 1])
    print(cm)
    print(f"   [[TN={cm[0][0]} FP={cm[0][1]}]")
    print(f"    [FN={cm[1][0]} TP={cm[1][1]}]]")
    attack_detection_rate = recall_score(y_true, y_pred_flag, pos_label=1, zero_division=0)
    print(f"\n>>> Attack Detection Rate (Recall for Malicious Class 1): {attack_detection_rate:.4f}")
    try:
        roc_auc = roc_auc_score(y_true, y_proba_clf)
        print(f"ROC AUC Score (based on classifier probability): {roc_auc:.4f}")
    except ValueError as e:
        print(f"Could not calculate ROC AUC: {e}") 

    try:
        precision, recall, _ = precision_recall_curve(y_true, y_proba_clf)
        avg_precision = average_precision_score(y_true, y_proba_clf)
        plt.figure(figsize=(8, 5))
        plt.plot(recall, precision, marker='.', label=f'Avg Precision = {avg_precision:.2f}')
        plt.xlabel('Recall (Attack Detection Rate)')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.show() 
    except ValueError as e:
         print(f"Could not generate Precision-Recall curve: {e}")
    except Exception as e:
         print(f"An error occurred during plotting: {e}")

    print("-----------------------------------")

if __name__ == "__main__":
    print("Initializing Security Log Analyzer...")
    analyzer = SecurityLogAnalyzer()
    if not analyzer.load_models():
        print("\nModels not found or failed to load. Starting training...")
        print(f"Generating synthetic training data ({TRAIN_FILE})...")
        simulator = ActivitySimulator()
        train_logs = simulator.generate_normal_activity(hours=240) 
        if not train_logs:
             print("ERROR: Failed to generate training data. Exiting.")
             exit()

        print(f"Writing {len(train_logs)} training logs to {TRAIN_FILE}...")
        try:
            with open(TRAIN_FILE, 'w') as f:
                for entry in train_logs:
                    f.write(json.dumps(entry) + '\n')
        except IOError as e:
             print(f"ERROR: Could not write training file {TRAIN_FILE}: {e}")
             exit()

        print("Training models...")
        if not analyzer.train(TRAIN_FILE):
             print("ERROR: Model training failed. Exiting.")
             exit()
        print("Training complete.")
    else:
        print("Using pre-trained models.")

    print(f"\nGenerating test data with mixed activities ({TEST_FILE})...")
    simulator = ActivitySimulator() 
    start_test_time = datetime.now() + timedelta(days=1) 
    normal_logs = simulator.generate_normal_activity(hours=2, start_time=start_test_time) 
    brute_force_logs = simulator.generate_malicious_activity(
        'brute_force', start_time=start_test_time + timedelta(minutes=30))
    exfiltration_logs = simulator.generate_malicious_activity(
        'data_exfiltration', start_time=start_test_time + timedelta(minutes=70))
    privilege_logs = simulator.generate_malicious_activity(
        'privilege_escalation', start_time=start_test_time + timedelta(minutes=100))
    test_data = normal_logs + brute_force_logs + exfiltration_logs + privilege_logs
    test_data.sort(key=lambda x: datetime.fromisoformat(x['raw_log']['timestamp']))
    print(f"Writing {len(test_data)} test logs to {TEST_FILE}...")
    try:
        with open(TEST_FILE, 'w') as f:
            for entry in test_data:
                f.write(json.dumps(entry) + '\n')
    except IOError as e:
        print(f"ERROR: Could not write test file {TEST_FILE}: {e}")
        exit()
    evaluate_model(analyzer, TEST_FILE)
    print("\n--- Starting Real-Time Monitoring Simulation ---")
    monitor = RealTimeMonitor(analyzer)
    processed_count = 0
    alert_count = 0
    try:
        with open(TEST_FILE, 'r') as f:
            simulation_data = []
            for line in f:
                try:
                    simulation_data.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.warning(f"Skipping malformed line in {TEST_FILE} during simulation.")

        if not simulation_data:
             raise ValueError("No data loaded for simulation")
        
        start_sim_time = time.time()
        for i, entry in enumerate(simulation_data):
            result = monitor.process_log(entry)
            processed_count += 1
            if result and result.get('is_malicious', False):
                 alert_count += 1

        end_sim_time = time.time()
        duration = end_sim_time - start_sim_time
        print(f"\nSimulation finished.")
        print(f"Processed {processed_count} log entries in {duration:.2f} seconds.")
        print(f"Generated {alert_count} alerts.")

    except FileNotFoundError:
        print(f"ERROR: Test file {TEST_FILE} not found for simulation.")
    except ValueError as e:
        print(f"ERROR during simulation setup: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during simulation: {e}")
    monitor.print_attack_summary()

    print("\n--- Security Model Simulation Complete ---")