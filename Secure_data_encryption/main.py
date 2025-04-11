import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import base64
import json
import os
from datetime import datetime, timedelta
import time

# ====== Constants ======
DATA_FILE = "data.json"
LOCK_FILE = "lock.json"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

# ====== Utility Functions ======
def ensure_json_file(filename):
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write("{}")

def load_json_file(filename):
    ensure_json_file(filename)
    with open(filename, "r") as f:
        content = f.read().strip()
        return json.loads(content) if content else {}

def save_json_file(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def generate_fernet_key(passkey):
    sha = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(sha)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text, passkey):
    key = generate_fernet_key(passkey)
    fernet = Fernet(key)
    return fernet.encrypt(text.encode()).decode()

def decrypt_text(ciphertext, passkey):
    key = generate_fernet_key(passkey)
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext.encode()).decode()

# ====== Session State Init ======
if "authorized" not in st.session_state:
    st.session_state.authorized = True

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

# ====== Load Data ======
data_store = load_json_file(DATA_FILE)
lock_store = load_json_file(LOCK_FILE)

# ====== Pages ======

def login_page():
    st.title("🔐 Admin Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            st.session_state.authorized = True
            st.success("Login successful!")
        else:
            st.error("Invalid credentials.")

def insert_data():
    st.title("📝 Store New Data")
    username = st.text_input("Enter Username")
    text = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Enter secret passkey", type="password")

    if st.button("Encrypt & Save"):
        if username and text and passkey:
            encrypted = encrypt_text(text, passkey)
            hashed_key = hash_passkey(passkey)
            data_store[username] = {
                "encrypted_text": encrypted,
                "passkey": hashed_key
            }
            save_json_file(DATA_FILE, data_store)
            st.success("Data encrypted and stored successfully.")
        else:
            st.warning("Please fill all fields.")

def retrieve_data():
    st.title("🔍 Retrieve Data")

    username = st.text_input("Username")
    encrypted_input = st.text_area("Encrypted Data")
    passkey = st.text_input("Enter your passkey", type="password")

    decrypt_clicked = st.button("🔓 Decrypt")

    if decrypt_clicked:
        if not username or not encrypted_input or not passkey:
            st.warning("All fields are required to retrieve data.")
            return

        if username not in data_store:
            st.error("User not found.")
            return

        # Check lock
        if username in lock_store:
            lock_time = datetime.strptime(lock_store[username], "%Y-%m-%d %H:%M:%S")
            now = datetime.now()
            remaining = (lock_time + timedelta(minutes=5)) - now

            if remaining.total_seconds() > 0:
                minutes, seconds = divmod(int(remaining.total_seconds()), 60)
                st.error(f"⏳ Data is locked. Try again in {minutes} min {seconds} sec.")
                time.sleep(1)
                st.rerun()
            else:
                del lock_store[username]
                save_json_file(LOCK_FILE, lock_store)
                st.success("🔓 Lock expired. You can try again.")
                st.rerun()

        stored_entry = data_store[username]

        if encrypted_input != stored_entry["encrypted_text"]:
            st.error("Encrypted data does not match stored data.")
            return

        hashed_input = hash_passkey(passkey)

        if hashed_input == stored_entry["passkey"]:
            try:
                decrypted = decrypt_text(stored_entry["encrypted_text"], passkey)
                st.success(f"✅ Decrypted Data:\n\n{decrypted}")
                st.session_state.failed_attempts[username] = 0
            except Exception:
                st.error("Decryption error.")
        else:
            st.error("❌ Incorrect passkey.")
            st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1

            if st.session_state.failed_attempts[username] >= 3:
                lock_store[username] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_json_file(LOCK_FILE, lock_store)
                st.warning("🔒 Too many failed attempts. Data locked for 5 minutes.")

def view_entries():
    st.title("📋 All Encrypted Entries")
    if not data_store:
        st.info("No entries found.")
        return

    for user, entry in data_store.items():
        st.markdown(f"**User:** `{user}`")
        st.code(entry["encrypted_text"], language="text")

def unlock_data():
    st.title("🔓 Unlock Locked Data (Admin Only)")
    username = st.text_input("Username to unlock")
    encrypted = st.text_area("Encrypted data (copy-paste)")
    admin_pass = st.text_input("Admin Password", type="password")

    if st.button("Unlock"):
        if admin_pass == ADMIN_PASSWORD and username in lock_store:
            if username in data_store and data_store[username]["encrypted_text"] == encrypted:
                del lock_store[username]
                save_json_file(LOCK_FILE, lock_store)
                st.success(f"{username}'s data has been unlocked.")
            else:
                st.error("Encrypted data does not match.")
        else:
            st.error("Invalid credentials or username not locked.")

# ====== Main App ======
def main():
    if not st.session_state.authorized:
        login_page()
        return

    st.sidebar.title("🔐 Secure Data Menu")
    choice = st.sidebar.radio("Select Page", ["Home", "Insert Data", "Retrieve Data", "View Entries", "Unlock Data"])

    if choice == "Home":
        st.title("🏠 Welcome to Secure Data App")
        st.write("Use the sidebar to manage encrypted data securely.")
    elif choice == "Insert Data":
        insert_data()
    elif choice == "Retrieve Data":
        retrieve_data()
    elif choice == "View Entries":
        view_entries()
    elif choice == "Unlock Data":
        unlock_data()

if __name__ == "__main__":
    main()
