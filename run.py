# run.py
import os
from secure_messaging.messenger import SecureMessenger
from secure_messaging.security_monitor import security_monitor
import getpass
import json
import logging 
from secure_messaging.logging_manager import global_logger

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    print("\nSecure Messaging System")
    print("1. Register User")
    print("2. Send Message")
    print("3. Send File")
    print("4. Check Messages")
    print("5. Decrypt Message")
    print("6. Decrypt File")
    print("7. Admin: View Security Logs")
    print("8. Exit")
    return input("Select an option (1-8): ")

def register_user(messenger):
    clear_screen()
    print("=== User Registration ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    
    if messenger.auth_system.user_exists(username):
        print("Error: Username already exists")
        input("Press Enter to continue...")
        return
    
    if messenger.auth_system.register_user(username, password):
        print("Registration successful!")
    else:
        print("Registration failed. Password must be at least 8 characters with uppercase, lowercase, number, and special character.")
    input("Press Enter to continue...")

def send_message(messenger):
    clear_screen()
    print("=== Send Message ===")
    username = input("Your username: ")
    password = getpass.getpass("Your password: ")
    recipient = input("Recipient username: ")
    message = input("Enter your message: ")
    
    result = messenger.send_message(username, password, recipient, message)
    print("\nResult:", result["message"])
    input("Press Enter to continue...")

def send_file(messenger):
    clear_screen()
    print("=== Send File ===")
    username = input("Your username: ")
    password = getpass.getpass("Your password: ")
    recipient = input("Recipient username: ")
    filepath = input("Path to text file to send: ")
    
    if not os.path.exists(filepath):
        print("Error: File not found")
        input("Press Enter to continue...")
        return
    
    result = messenger.send_file(username, password, recipient, filepath)
    print("\nResult:", result["message"])
    if result["status"] == "error" and "Only .txt files are supported" in result["message"]:
        print("Please provide only .txt files for encryption")
    input("Press Enter to continue...")

def check_messages(messenger):
    clear_screen()
    print("=== Your Received Messages and Files ===")
    username = input("Your username: ")
    password = getpass.getpass("Your password: ")
    
    result = messenger.receive_messages(username, password)
    
    if result["status"] == "error":
        print("\nError:", result["message"])
    elif not result["items"]:
        print("\nNo received messages or files")
    else:
        print("\nReceived Items:")
        for idx, item in enumerate(result["items"], 1):
            type_display = "Message" if item['type'] == 'message' else "File"
            print(f"{idx}. Type: {type_display} | From: {item['sender']} | Time: {item['timestamp']}")
        
        choice = input("\nEnter item number to read/decrypt (0 to cancel): ")
        if choice.isdigit() and 0 < int(choice) <= len(result["items"]):
            selected_item = result["items"][int(choice)-1]
            
            if selected_item['type'] == 'message':
                decrypted = messenger.decrypt_and_delete_message(username, password, selected_item['path'])
                
                print("\n" + "="*50)
                if decrypted["status"] == "success":
                    print("Decrypted Message:")
                    print(decrypted["message"])
                elif decrypted.get("code") == "INTEGRITY_FAILURE":
                    print("‼️ CRITICAL SECURITY ALERT ‼️")
                    print(decrypted["message"])
                    print("Warning: This message may have been modified by a third party!")
                else:
                    print("Error:", decrypted["message"])
                print("="*50)
            elif selected_item['type'] == 'file':
                try:
                    output_path = input("Enter path to save decrypted file (e.g., C:/downloads/filename.txt): ")
                    if not output_path.lower().endswith('.txt'):
                        print("Error: Only .txt files are supported for decryption")
                        input("Press Enter to continue...")
                        
                    result = messenger.decrypt_file(username, password, selected_item['path'], output_path)
                    print("\n" + "="*50)
                    if result["status"] == "success":
                        print("File Decrypted Successfully!")
                        print("Saved to:", result.get("output_path", output_path))
                    else:
                        print("Error decrypting file:", result.get("message", "Unknown error"))
                    print("="*50)
                except Exception as e:
                    print(f"Error processing file: {e}")
    
    input("\nPress Enter to continue...")

def decrypt_message(messenger):
    clear_screen()
    print("=== Decrypt Messages ===")
    username = input("Your username: ")
    password = getpass.getpass("Your password: ")
    
    result = messenger.receive_only_messages(username, password)
    
    if result["status"] == "error":
        print("\nError:", result["message"])
    elif not result["items"]:
        print("\nNo received messages")
    else:
        print("\nReceived Messages:")
        for idx, message in enumerate(result["items"], 1):
            print(f"{idx}. From: {message['sender']} | Time: {message['timestamp']}")
        
        choice = input("\nEnter message number to read/decrypt (0 to cancel): ")
        if choice.isdigit() and 0 < int(choice) <= len(result["items"]):
            selected_message = result["items"][int(choice)-1]
            
            decrypted = messenger.decrypt_and_delete_message(username, password, selected_message['path'])
            
            print("\n" + "="*50)
            if decrypted["status"] == "success":
                print("Decrypted Message:")
                print(decrypted["message"])
            elif decrypted.get("code") == "INTEGRITY_FAILURE":
                print("‼️ CRITICAL SECURITY ALERT ‼️")
                print(decrypted["message"])
                print("Warning: This message may have been modified by a third party!")
            else:
                print("Error:", decrypted["message"])
            print("="*50)
    
    input("\nPress Enter to continue...")

def decrypt_file(messenger):
    clear_screen()
    print("=== Decrypt File ===")
    username = input("Your username: ")
    password = getpass.getpass("Your password: ")
    file_result = messenger.receive_files_only(username, password)
    
    if file_result["status"] == "error":
        print("Error:", file_result["message"])
        input("Press Enter to continue...")
        return
    
    files = file_result.get("items", [])
    
    if not files:
        print("No encrypted files available")
        input("Press Enter to continue...")
        return
    
    print("\nEncrypted Files:")
    for idx, file in enumerate(files, 1):
        print(f"{idx}. From: {file['sender']} | Received: {file['timestamp']}")
    
    try:
        choice = int(input("\nSelect file to decrypt (0 to cancel): "))
        if choice == 0:
            return
        selected = files[choice-1]
    except (ValueError, IndexError):
        print("Invalid selection")
        input("Press Enter to continue...")
        return
    
    output_path = input("Enter path to save decrypted file: ")
    result = messenger.decrypt_file(username, password, selected['path'], output_path)

    if result["status"] == "error":
        if result.get("code") == "AUTHENTICATION_FAILED":
            print("SECURITY ALERT: Authentication failed - attempt logged")
        else:
            print("Decryption failed:", result["message"])
    else:
        print("Successfully decrypted to:", output_path)
    
    input("Press Enter to continue...")

def receive_messages(self, user: str, password: str, sender: str = None) -> dict:
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
                if msg_file.endswith('.enc') and (msg_file.startswith('msg_') or msg_file.startswith('file_')):
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

def view_security_logs(messenger):
    clear_screen()
    username = input("Admin username: ")
    password = getpass.getpass("Admin password: ")
    
    if not security_monitor.is_admin(username, password):
        print("Access denied: Invalid admin credentials")
        input("Press Enter to continue...")
        return
    
    try:
        admin_log_file = os.path.join("security_logs", "admin_threats.jsonl")
        if not os.path.exists(admin_log_file):
            print("No security threats detected")
            input("Press Enter to continue...")
            return
            
        threats = []
        with open(admin_log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                try:
                    threat = json.loads(line)
                    threats.append(threat)
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping malformed log entry - {e}")
                    continue
            
            if not threats:
                print("No valid security threats detected")
                input("Press Enter to continue...")
                return
                
            # Group by threat type
            threat_counts = {}
            for t in threats:
                threat_type = t.get('specific_threat_type', 'GENERIC_ANOMALY')
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            
            print("\n=== Security Threat Dashboard ===")
            print("\nThreat Summary:")
            for threat, count in sorted(threat_counts.items()):
                print(f"- {threat}: {count} occurrences")
            
            print("\nRecent Threats (last 5):")
            for threat in threats[-5:]:
                print(f"\n[{threat.get('timestamp')}] {threat.get('specific_threat_type')}")
                print(f"User: {threat.get('username')}")
                print(f"Event: {threat.get('triggering_event_type')}")
                indicators = threat.get('Key Indicators', threat.get('key_features', {}))
                if indicators:
                    print("Key Indicators:")
                    for k, v in indicators.items():
                        if v and v != 0 and v != 'none':
                            print(f"  {k}: {v}")
    except Exception as e:
        print(f"Error viewing logs: {e}")
    
    input("\nPress Enter to continue...")
    
def main():
    messenger = SecureMessenger()
    import warnings
    warnings.filterwarnings("ignore")
    logging.getLogger().setLevel(logging.CRITICAL)
    while True:
        clear_screen()
        choice = display_menu()
        
        if choice == "1":
            register_user(messenger)
        elif choice == "2":
            send_message(messenger)
        elif choice == "3":
            send_file(messenger)
        elif choice == "4":
            check_messages(messenger)
        elif choice == "5":
            decrypt_message(messenger)
        elif choice == "6":
            decrypt_file(messenger)
        elif choice == "7":
            view_security_logs(messenger)
        elif choice == "8":
            print("Exiting...")
            messenger.auth_system.close()
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()