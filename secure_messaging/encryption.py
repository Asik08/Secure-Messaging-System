# encryption.py
import base64
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
import hashlib
from datetime import datetime

class SecureEncryption:
    def __init__(self, password: str):
        self.password = password
        self.enc_key, self.auth_key = self._derive_keys(password)

    def _derive_keys(self, password: str):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=64,
            salt=b'secure_salt_',
            iterations=600000
        )
        keys = kdf.derive(password.encode())
        return keys[:32], keys[32:]

    def encrypt_message(self, message: str) -> dict:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.enc_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        h = hmac.HMAC(self.auth_key, hashes.SHA256())
        h.update(ciphertext)
        mac = h.finalize()
        checksum_data = {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'mac': base64.b64encode(mac).decode()
        }
        checksum = hashlib.sha256(
            json.dumps(checksum_data, sort_keys=True).encode()
        ).hexdigest()
        return {
            **checksum_data,
            'checksum': checksum,
            'metadata': {
                'version': '1.1',
                'timestamp': datetime.now().isoformat()
            }
        }

    def encrypt_file(self, input_path: str, output_path: str):
        try:
            if not input_path.lower().endswith('.txt'):
                raise ValueError("UNSUPPORTED_FILE_TYPE")
                
            with open(input_path, 'rb') as f:
                try:
                    plaintext = f.read().decode('utf-8')
                except UnicodeDecodeError:
                    raise ValueError("INVALID_TEXT_FILE")
                    
            encrypted = self.encrypt_message(plaintext)
            with open(output_path, 'w') as f:
                json.dump(encrypted, f)
                
        except ValueError as ve:
            if str(ve) == "UNSUPPORTED_FILE_TYPE":
                raise ValueError("Only .txt files are supported")
            elif str(ve) == "INVALID_TEXT_FILE":
                raise ValueError("File is not valid UTF-8 text")
            raise
        except Exception as e:
            raise ValueError(f"File encryption failed: {str(e)}")
       
    def decrypt_message(self, encrypted_data: dict) -> str:
        try:
            required_fields = ['iv', 'ciphertext', 'tag', 'mac', 'checksum']
            if not all(field in encrypted_data for field in required_fields):
                missing = [f for f in required_fields if f not in encrypted_data]
                raise ValueError(f"MISSING_FIELDS:{','.join(missing)}")

            current_data = {k: encrypted_data[k] for k in ['iv', 'ciphertext', 'tag', 'mac']}
            current_checksum = hashlib.sha256(
                json.dumps(current_data, sort_keys=True).encode()
            ).hexdigest()
            
            if current_checksum != encrypted_data['checksum']:
                modified_fields = []
                for field in ['iv', 'ciphertext', 'tag', 'mac']:
                    temp_data = current_data.copy()
                    temp_data[field] = 'MODIFIED'
                    temp_checksum = hashlib.sha256(
                        json.dumps(temp_data, sort_keys=True).encode()
                    ).hexdigest()
                    if temp_checksum == encrypted_data['checksum']:
                        modified_fields.append(field)
                
                if modified_fields:
                    raise ValueError(f"TAMPERED_FIELDS:{','.join(modified_fields)}")
                raise ValueError("CHECKSUM_MISMATCH")

            try:
                iv = base64.b64decode(encrypted_data['iv'].encode())
                ciphertext = base64.b64decode(encrypted_data['ciphertext'].encode())
                tag = base64.b64decode(encrypted_data['tag'].encode())
                mac = base64.b64decode(encrypted_data['mac'].encode())
            except (binascii.Error, AttributeError) as e:
                raise ValueError(f"INVALID_ENCODING:{str(e)}")

            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(ciphertext)
            try:
                h.verify(mac)
            except Exception:
                raise ValueError("HMAC_FAILURE")

            cipher = Cipher(algorithms.AES(self.enc_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode()

        except ValueError as ve:
            raise
        except Exception as e:
            raise ValueError(f"DECRYPTION_ERROR:{str(e)}")