# messenger.py
import os
import json
from datetime import datetime,timezone
from .authentication import UserAuthentication
from .encryption import SecureEncryption
from .logging_manager import global_logger
import secrets
from .security_monitor import security_monitor
import warnings
import logging
warnings.filterwarnings("ignore")
monitor_logger = logging.getLogger('SecurityMonitor')

class SecureMessenger:
    def __init__(self):
        self.auth_system = UserAuthentication()
        self.cloud_storage = "CloudStorage"
        os.makedirs(self.cloud_storage, exist_ok=True)

    def _get_conversation_dir(self, user1: str, user2: str) -> str:
        conversation_id = f"{min(user1, user2)}_{max(user1, user2)}"
        path = os.path.join(self.cloud_storage, conversation_id)
        os.makedirs(path, exist_ok=True)
        return path
    
    def receive_only_messages(self, user: str, password: str, sender: str = None) -> dict:
        return self.receive_messages(user, password, sender, include_files=False)
    
    def _save_message(self, sender: str, recipient: str, encrypted_data: dict, is_file: bool = False):
        if sender == recipient:
            ml_entry = {
                'raw_log': {
                    'username': sender,
                    'event_type': 'SELF_SEND_ATTEMPT',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'recipient': recipient,
                    'status': 'blocked',
                    'content_type': 'file' if is_file else 'message',
                    'error_code': 'SELF_SEND'
                },
                'ml_features': {
                    'event_category': 'security',
                    'event_action': 'self_send',
                    'success': 0,
                    'error_occurred': 1,
                    'is_after_hours': 1 if not (8 <= datetime.now(timezone.utc).hour <= 17) else 0,
                    'requests_last_5min': 0,
                    'recipient_id': 'self',
                    'integrity_verified': 1  
                }
            }
            security_monitor.check_security(ml_entry)
            raise ValueError("Cannot send to self")
        
        recipient_dir = os.path.join(self.cloud_storage, f"inbox_{recipient}")
        os.makedirs(recipient_dir, exist_ok=True)
        
        file_prefix = "file" if is_file else "msg"
        filename = f"{file_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}.enc"
        filepath = os.path.join(recipient_dir, filename)
        
        encrypted_data['metadata'] = {
            'sender': sender,
            'recipient': recipient,
            'timestamp': datetime.now().isoformat(),
            'is_read': False,
            'type': 'file' if is_file else 'message'
        }
        
        with open(filepath, 'w') as f:
            json.dump(encrypted_data, f)
        os.chmod(filepath, 0o600)
        return filepath

    def send_message(self, sender: str, sender_password: str, recipient: str, message: str) -> dict:
        log_data = {
            'username': sender,
            'event_type': 'MESSAGE_SEND',
            'recipient': recipient,
            'message_length': len(message),
            'direction': 'outgoing',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            global_logger.log_event('activity', {**log_data, 'status': 'attempt'})
            
            if sender == recipient:
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'SELF_SEND_ATTEMPT',
                    'status': 'failed',
                    'error_code': 'SELF_SEND'
                })
                return {"status": "error", "message": "Cannot send message to yourself"}

            if not self.auth_system.user_exists(sender):
                return {"status": "error", "message": "Sender account does not exist"}

            if not self.auth_system.authenticate_user(sender, sender_password):
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'AUTHENTICATION_FAILURE',
                    'action': 'send_message',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Authentication failed - incorrect password"}

            if not self.auth_system.user_exists(recipient):
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'INVALID_RECIPIENT',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Recipient does not exist"}

            encryption = SecureEncryption(sender_password)
            encrypted_data = encryption.encrypt_message(message)
            
            encrypted_data['metadata'] = {
                'sender': sender,
                'recipient': recipient,
                'timestamp': datetime.now().isoformat(),
                'is_read': False,
                'type': 'message'
            }
            
            filepath = self._save_message(sender, recipient, encrypted_data)
            
            global_logger.log_event('activity', {
                **log_data,
                'status': 'success',
                'filepath': filepath,
                'encryption_status': 'success'
            })
            
            return {
                "status": "success",
                "message": "Message sent successfully",
                "filepath": filepath
            }

        except Exception as e:
            global_logger.log_event('security', {
                'username': sender,
                'event_type': 'MESSAGE_SEND_FAILURE',
                'status': 'failed',
                'error_code': str(e)
            })
            return {"status": "error", "message": str(e)}

    def send_file(self, sender: str, sender_password: str, 
                 recipient: str, filepath: str) -> dict:
        log_data = {
            'username': sender,
            'event_type': 'FILE_SEND',
            'recipient': recipient,
            'original_path': filepath,
            'direction': 'outgoing'
        }

        try:
            global_logger.log_event('activity', {**log_data, 'status': 'attempt'})

            if sender == recipient:
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'SELF_SEND_ATTEMPT',
                    'status': 'failed',
                    'error_code': 'SELF_SEND'
                })
                return {"status": "error", "message": "Cannot send to yourself"}

            if not filepath.lower().endswith('.txt'):
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'INVALID_FILE_TYPE',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Only .txt files are supported"}

            if not self.auth_system.authenticate_user(sender, sender_password):
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'AUTHENTICATION_FAILURE',
                    'action': 'send_file',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Sender authentication failed"}

            if not self.auth_system.user_exists(recipient):
                global_logger.log_event('security', {
                    'username': sender,
                    'event_type': 'INVALID_RECIPIENT',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Recipient does not exist"}
            
            with open(filepath, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            encryption = SecureEncryption(sender_password)
            encrypted = encryption.encrypt_message(file_content)
            saved_path = self._save_message(sender, recipient, encrypted, is_file=True)
            
            global_logger.log_event('activity', {
                **log_data,
                'status': 'success',
                'encrypted_path': saved_path,
                'file_size': len(file_content),
                'encryption_status': 'success'
            })
            
            global_logger.log_event('security', {
                'username': sender,
                'event_type': 'FILE_SEND_SUCCESS',
                'status': 'success',
                'encryption_status': 'success',
                'integrity_check': 'passed'
            })
            
            return {
                "status": "success",
                "message": "File sent securely",
                "path": saved_path
            }

        except Exception as e:
            global_logger.log_event('security', {
                'username': sender,
                'event_type': 'FILE_SEND_FAILURE',
                'status': 'failed',
                'error_code': str(e)
            })
            return {"status": "error", "message": str(e)}

    def receive_messages(self, user: str, password: str, sender: str = None, include_files: bool = True) -> dict:
        log_data = {
            'username': user,
            'event_type': 'MESSAGES_RECEIVE',
            'direction': 'incoming',
            'sender_filter': sender
        }

        try:
            global_logger.log_event('activity', {**log_data, 'status': 'attempt'})

            if not self.auth_system.authenticate_user(user, password):
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'AUTHENTICATION_FAILURE',
                    'action': 'receive_messages',
                    'status': 'failed'
                })
                return {"status": "error", "message": "Authentication failed"}
            
            inbox_dir = os.path.join(self.cloud_storage, f"inbox_{user}")
            received_items = []
            
            if os.path.exists(inbox_dir):
                for msg_file in os.listdir(inbox_dir):
                    if msg_file.endswith('.enc'):
                        if (msg_file.startswith('msg_') or 
                            (include_files and msg_file.startswith('file_'))):
                            msg_path = os.path.join(inbox_dir, msg_file)
                            try:
                                with open(msg_path, 'r') as f:
                                    encrypted_data = json.load(f)
                                
                                if encrypted_data.get('metadata', {}).get('recipient') == user:
                                    if not sender or encrypted_data['metadata']['sender'] == sender:
                                        received_items.append({
                                            'path': msg_path,
                                            'sender': encrypted_data['metadata']['sender'],
                                            'timestamp': encrypted_data['metadata']['timestamp'],
                                            'type': encrypted_data['metadata'].get('type', 'unknown')
                                        })
                            except Exception:
                                continue
            
            global_logger.log_event('activity', {
                **log_data,
                'status': 'success',
                'item_count': len(received_items)
            })
            
            global_logger.log_event('security', {
                'username': user,
                'event_type': 'MESSAGES_RECEIVE_SUCCESS',
                'status': 'success',
                'item_count': len(received_items)
            })
            
            return {"status": "success", "items": received_items}

        except Exception as e:
            global_logger.log_event('security', {
                'username': user,
                'event_type': 'MESSAGES_RECEIVE_FAILURE',
                'status': 'failed',
                'error_code': str(e)
            })
            return {"status": "error", "message": str(e)}

    def decrypt_and_delete_message(self, user: str, password: str, msg_path: str):
        log_data = {
            'username': user,
            'event_type': 'MESSAGE_DECRYPT',
            'message_path': msg_path
        }

        try:
            global_logger.log_event('activity', {**log_data, 'status': 'attempt'})

            with open(msg_path, 'r') as f:
                encrypted_data = json.load(f)

            if encrypted_data.get('metadata', {}).get('recipient') != user:
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'UNAUTHORIZED_ACCESS',
                    'status': 'failed',
                    'error_code': 'WRONG_RECIPIENT'
                })
                return {
                    "status": "error",
                    "message": "Access denied",
                    "code": "UNAUTHORIZED"
                }
            
            if not self.auth_system.authenticate_user(user, password):
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'AUTHENTICATION_FAILURE',  
                    'action': 'decrypt_message', 
                    'status': 'failed'
                })
                return {"status": "error", "message": "Authentication failed"}

            encryption = SecureEncryption(password)
            plaintext = encryption.decrypt_message(encrypted_data)
            
            global_logger.log_event('activity', {
                **log_data,
                'status': 'success',
                'sender': encrypted_data['metadata']['sender'],
                'message_length': len(plaintext),
                'encryption_status': 'success'
            })
            
            global_logger.log_event('security', {
                'username': user,
                'event_type': 'MESSAGE_DECRYPT_SUCCESS',
                'status': 'success',
                'encryption_status': 'success',
                'integrity_check': 'passed'
            })

            os.remove(msg_path)
            return {"status": "success", "message": plaintext}

        except ValueError as ve:
            error_code = str(ve)
            if "TAMPERED_FIELDS" in error_code or "CHECKSUM_MISMATCH" in error_code:
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'INTEGRITY_FAILURE',
                    'status': 'failed',
                    'error_code': error_code.split(':')[0],
                    'integrity_check': 'failed',
                    'operation_type': 'message'
                })
                ml_entry = {
                    'raw_log': {
                        'username': user,
                        'event_type': 'MESSAGE_DECRYPT_FAILURE',
                        'status': 'failed',
                        'error_code': error_code.split(':')[0]
                    },
                    'ml_features': {
                        'integrity_verified': 0,
                        'event_category': 'security',
                        'success': 0,
                        'error_occurred': 1
                    }
                }
                security_monitor.check_security(ml_entry)

            try:
                if os.path.exists(msg_path):
                    os.remove(msg_path)
            except Exception as e:
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'FILE_DELETION_FAILURE',
                    'status': 'failed',
                    'error_code': str(e)
                })
            
            if error_code.startswith("TAMPERED_FIELDS:"):
                return {
                    "status": "error",
                    "message": f"‼️ TAMPERING DETECTED ‼️\nModified fields: {', '.join(error_code.split(':')[1].split(','))}",
                    "code": "TAMPERED_FIELDS"
                }
            elif error_code == "CHECKSUM_MISMATCH":
                return {
                    "status": "error",
                    "message": "‼️ INTEGRITY FAILURE ‼️\nMessage checksum invalid",
                    "code": "CHECKSUM_FAILURE"
                }
            elif error_code == "HMAC_FAILURE":
                self.security_log_dir = "security_logs"
                self.admin_threat_log_file = os.path.join(self.security_log_dir, "admin_threats.jsonl")
                global_logger.log_event('security', {
                    'username': user,
                    'event_type': 'AUTHENTICATION_FAILED',
                    'status': 'failed',
                    'error_code': 'AUTHENTICATION_FAILED'
                })
                threat_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "specific_threat_type": "AUTHENTICATION_FAILURE",
                    "username": user,
                    "triggering_event_type": "AUTHENTICATION_FAILURE",
                    "error": 'AUTHENTICATION_FAILURE' 
                }
                
                try:
                    with open(self.admin_threat_log_file, 'a') as f:
                        json.dump(threat_entry, f)
                        f.write('\n')  
                except Exception as e:
                    monitor_logger.error(f"Failed to log self-send attempt: {str(e)}")
                return {
                    "status": "error",
                    "message": "‼️ SECURITY ALERT ‼️\nMessage authentication failed",
                    "code": "AUTHENTICATION_FAILED"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Decryption failed: {error_code}",
                    "code": "DECRYPTION_FAILED"
                }
    def receive_files_only(self, user: str, password: str) -> dict:
        result = self.receive_messages(user, password, include_files=True)
        if result["status"] == "success":
            result["items"] = [item for item in result["items"] if item['type'] == 'file']
        return result
    
    def decrypt_file(self, username: str, password: str, input_path: str, output_path: str) -> dict:
        log_data = {
        'username': username,
        'event_type': 'FILE_DECRYPT',
        'input_path': input_path,
        'output_path': output_path
    }

        try:
            global_logger.log_event('activity', {**log_data, 'status': 'attempt'})

            if not self.auth_system.authenticate_user(username, password):
                global_logger.log_event('security', {
                    'username': username,
                    'event_type': 'AUTHENTICATION_FAILURE',
                    'status': 'failed',
                    'error_code': 'WRONG_PASSWORD',
                    'action': 'decrypt_file',  
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                return {"status": "error", "message": "Authentication failed"}
            
            with open(input_path, 'r') as f:
                encrypted_data = json.load(f)
            
            metadata = encrypted_data.get('metadata', {})
            if metadata.get('recipient') != username:
                global_logger.log_event('security', {
                    'username': username,
                    'event_type': 'UNAUTHORIZED_ACCESS',
                    'status': 'failed',
                    'error_code': 'WRONG_RECIPIENT'
                })
                return {"status": "error", "message": "Access denied"}
            
            encryption = SecureEncryption(password)
            plaintext = encryption.decrypt_message(encrypted_data)
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(plaintext)
            
            global_logger.log_event('activity', {
                **log_data,
                'status': 'success',
                'file_size': len(plaintext),
                'encryption_status': 'success'
            })
            
            global_logger.log_event('security', {
                'username': username,
                'event_type': 'FILE_DECRYPT_SUCCESS',
                'status': 'success',
                'encryption_status': 'success',
                'integrity_check': 'passed'
            })

            os.remove(input_path)
            return {
                "status": "success",
                "message": "File decrypted",
                "output_path": output_path
            }
            
        except ValueError as ve:
            error_code = str(ve)
            try:
                if os.path.exists(input_path):
                    os.remove(input_path)
            except Exception as e:
                global_logger.log_event('security', {
                    'username': username,
                    'event_type': 'FILE_DELETION_FAILURE',
                    'status': 'failed',
                    'error_code': str(e)
                })

            if "TAMPERED_FIELDS" in error_code or "CHECKSUM_MISMATCH" in error_code:
                global_logger.log_event('security', {
                    'username': username,
                    'event_type': 'INTEGRITY_FAILURE',
                    'status': 'failed',
                    'error_code': error_code.split(':')[0],
                    'integrity_check': 'failed',
                    'operation_type': 'file'
                })
                ml_entry = {
                    'raw_log': {
                        'username': username,
                        'event_type': 'FILE_DECRYPT_FAILURE',
                        'status': 'failed',
                        'error_code': error_code.split(':')[0]
                    },
                    'ml_features': {
                        'integrity_verified': 0,
                        'event_category': 'security',
                        'success': 0,
                        'error_occurred': 1
                    }
                }
                security_monitor.check_security(ml_entry)

            return {"status": "error", "message": str(ve)}
        except Exception as e:
            global_logger.log_event('security', {
                'username': username,
                'event_type': 'FILE_DECRYPT_FAILURE',
                'status': 'failed',
                'error_code': str(e)
            })
            return {"status": "error", "message": str(e)}