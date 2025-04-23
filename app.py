import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# --- Session State Setup ---
if "data" not in st.session_state:
    st.session_state.data = {}
if "attempts" not in st.session_state:
    st.session_state.attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# --- Helper Functions ---
def hash_passkey(key):
    return hashlib.sha256(key.encode()).hexdigest()

# --- Home Page ---
def home():
    st.title("🔐 Secure Data App")
    st.write("Welcome to the Secure Data Encryption App!")
    st.markdown("➡️ Use the sidebar to Insert or Retrieve data securely.")

# --- Insert Data Page ---
def insert_page():
    st.title("📝 Insert Data")
    username = st.text_input("Username")
    text = st.text_area("Text to Encrypt")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Encrypt & Store"):
        if username and text and passkey:
            fernet_key = Fernet.generate_key()
            fernet = Fernet(fernet_key)
            encrypted_text = fernet.encrypt(text.encode()).decode()

            st.session_state.data[username] = {
                "encrypted": encrypted_text,
                "fernet_key": fernet_key.decode(),
                "passkey": hash_passkey(passkey)
            }

            st.success("✅ Data stored successfully!")
            st.code(encrypted_text)
        else:
            st.warning("⚠️ Please fill all fields.")

# --- Retrieve Data Page ---
def retrieve_page():
    st.title("🔍 Retrieve Data")

    if not st.session_state.authorized:
        st.warning("🔐 Too many failed attempts. Please log in again.")
        login_page()
        return

    username = st.text_input("Username")
    passkey = st.text_input("Passkey", type="password")

    if st.button("Decrypt"):
        if username in st.session_state.data:
            stored = st.session_state.data[username]
            if hash_passkey(passkey) == stored["passkey"]:
                fernet = Fernet(stored["fernet_key"].encode())
                decrypted = fernet.decrypt(stored["encrypted"].encode()).decode()
                st.success("🔓 Decrypted Text:")
                st.code(decrypted)
                st.session_state.attempts = 0
            else:
                st.session_state.attempts += 1
                st.error(f"❌ Wrong passkey! Attempts: {st.session_state.attempts}/3")
                if st.session_state.attempts >= 3:
                    st.session_state.authorized = False
        else:
            st.warning("⚠️ Username not found.")

# --- Login Page ---
def login_page():
    st.title("🔐 Login Page")
    username = st.text_input("Enter admin username")
    password = st.text_input("Enter admin password", type="password")

    if st.button("Login"):
        if username == "atif" and password == "atif123":
            st.success("✅ Logged in successfully.")
            st.session_state.authorized = True
            st.session_state.attempts = 0
        else:
            st.error("❌ Invalid credentials.")

# --- Sidebar Navigation ---
st.sidebar.title("📂 Menu")
page = st.sidebar.radio("Select Page", ["Home", "Insert", "Retrieve", "Login"])

if page == "Home":
    home()
elif page == "Insert":
    insert_page()
elif page == "Retrieve":
    retrieve_page()
elif page == "Login":
    login_page()
