# Secure Messaging System 🔒

A secure end-to-end encrypted messaging platform with real-time security monitoring, anomaly detection, and tamper-proof message/file exchange.  
**Key Features**: AES-GCM Encryption • Brute-Force Protection • HMAC Integrity Checks • ML-Powered Threat Detection.


## Features ✨
- **Secure Messaging**: Encrypted text/file exchange with SHA-256 checksum validation
- **Multi-Layer Security**:
  - PBKDF2-HMAC user authentication
  - Tamper detection via HMAC signatures
  - Automatic file/message deletion after decryption
- **Threat Monitoring**:
  - Isolation Forest anomaly detection
  - Random Forest classifier for malicious patterns
  - Real-time alerts for brute-force attacks, data exfiltration, and integrity violations
- **Admin Dashboard**: View security logs, threat statistics, and system alerts


```bash
# Clone repository
git clone https://github.com/yourusername/secure-messaging-system.git
cd secure-messaging-system
```

## Usage 🚀
```bash
python -m secure_messaging.run
```

## Main Menu Options:

Register User: Strong password policy enforced (8+ chars, mix of cases, symbols)

Send Message: Encrypted text communication

Send File: Secure .txt file transfer only

Check Messages: View/decrypt received items with auto-integrity checks

Admin Security Logs: View threat dashboard (credentials: admin/admin123)


## Project Structure 📁
```
.
├── secure_messaging/
│   ├── messenger.py          # Core messaging logic
│   ├── encryption.py         # AES/HMAC implementation
│   ├── authentication.py     # User auth & session management
│   ├── security_monitor.py   # Real-time threat detection
│   ├── security_model.py     # ML model training/prediction
│   └── logging_manager.py    # Unified logging system
├── models/                   # Pre-trained ML models
│   ├── anomaly_detector.joblib
│   └── security_classifier.joblib
├── datasets/                 # Sample security logs
│   ├── synthetic_logs.jsonl  # Training data
│   └── test_logs.jsonl       # Evaluation data
├── run.py                    # CLI interface
└── requirements.txt
```

## Dataset & Models 📊

#### Included Resources:

synthetic_logs.jsonl: 240 hours of simulated normal/malicious activity

test_logs.jsonl: Validation dataset with labeled anomalies

Pre-trained models (retrain if needed):
```bash
python -m secure_messaging.security_model --train
```

## Model Architectures:

Anomaly Detector: Isolation Forest (200 estimators)

Threat Classifier: Random Forest (200 estimators, max_depth=15)
