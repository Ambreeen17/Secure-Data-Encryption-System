import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# ---- App Setup ----
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="centered")

# ---- Load/Generate Encryption Key ----
KEY_FILE = "fernet.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)
cipher = Fernet(KEY)

# ---- Load/Prepare Storage ----
DATA_FILE = "secure_data.json"
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# ---- Session State ----
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ---- Helpers ----
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_pass = hash_passkey(passkey)
    for data in stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_pass:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# ---- Sidebar ----
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/lock.png", width=60)
    st.title("Secure Vault")
    st.markdown("*Encrypt. Store. Retrieve.*")
    choice = st.selectbox("Navigation", ["Home", "Store Data", "Retrieve Data", "Login"])
    st.markdown("---")
    st.caption("Built with ❤️ by Ambreen Rais")

# ---- Main Area ----
st.markdown("<style>h1 {color: #0e76a8;}</style>", unsafe_allow_html=True)

if choice == "Home":
    st.header("🏠 Welcome to Your Secure Vault")
    st.markdown("""
        - Store your sensitive data securely.
        - Retrieve it using your unique passkey.
        - Three failed attempts will lock access.
    """)
    st.info("Navigate using the sidebar to get started.")

elif choice == "Store Data":
    st.header("📂 Store Your Data Securely")
    data_id = st.text_input("Unique Data ID", placeholder="e.g. bank_note")
    user_data = st.text_area("Enter your sensitive data here:")
    passkey = st.text_input("Create a secure passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if data_id and user_data and passkey:
            if data_id in stored_data:
                st.warning("⚠ That Data ID already exists.")
            else:
                encrypted = encrypt_data(user_data)
                stored_data[data_id] = {
                    "encrypted_text": encrypted,
                    "passkey": hash_passkey(passkey)
                }
                save_data()
                st.success("✅ Your data was encrypted and saved securely!")
        else:
            st.error("❗ Please complete all fields before saving.")

elif choice == "Retrieve Data":
    st.header("🔍 Retrieve Encrypted Data")
    data_id = st.text_input("Enter your Data ID")
    passkey = st.text_input("Enter your Passkey", type="password")

    if st.button("🔓 Decrypt"):
        if data_id and passkey:
            if data_id in stored_data:
                encrypted_text = stored_data[data_id]["encrypted_text"]
                decrypted = decrypt_data(encrypted_text, passkey)

                if decrypted:
                    st.success("✅ Success! Your decrypted data:")
                    st.code(decrypted, language="text")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Redirecting to login...")
                        st.experimental_rerun()
            else:
                st.error("⚠ Data ID not found.")
        else:
            st.error("❗ Please enter both fields.")

elif choice == "Login":
    st.header("🔑 Reauthentication")
    st.markdown("Please reauthorize to continue after failed attempts.")
    login_pass = st.text_input("Enter Master Password", type="password")
    if st.button("✅ Login"):
        if login_pass == "admin123":  # Change for production
            st.session_state.failed_attempts = 0
            st.success("✅ Access restored. Redirecting...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password.")
