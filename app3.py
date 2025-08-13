import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import uuid
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
import os

# --- Local Storage Configuration ---
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Firebase Initialization ---
@st.cache_resource
def init_firebase():
    if not firebase_admin._apps:
        try:
            cred_dict = {
                "type": st.secrets["firebase"]["type"],
                "project_id": st.secrets["firebase"]["project_id"],
                "private_key_id": st.secrets["firebase"]["private_key_id"],
                "private_key": st.secrets["firebase"]["private_key"],
                "client_email": st.secrets["firebase"]["client_email"],
                "client_id": st.secrets["firebase"]["client_id"],
                "auth_uri": st.secrets["firebase"]["auth_uri"],
                "token_uri": st.secrets["firebase"]["token_uri"],
                "auth_provider_x509_cert_url": st.secrets["firebase"]["auth_provider_x509_cert_url"],
                "client_x509_cert_url": st.secrets["firebase"]["client_x509_cert_url"],
                "universe_domain": st.secrets["firebase"]["universe_domain"],
            }
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
        except Exception as e:
            st.error(f"Firebase secrets not configured. Check your .streamlit/secrets.toml file. Error: {e}")
            st.stop()
    return firestore.client()

db = init_firebase()

# --- Helper Functions ---

def save_file_locally(uploaded_file, file_id):
    try:
        unique_filename = f"{file_id}_{uploaded_file.name}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return unique_filename
    except Exception as e:
        st.error(f"Error saving file locally: {e}")
        return None

def get_local_file_content(saved_filename):
    try:
        file_path = os.path.join(UPLOAD_FOLDER, saved_filename)
        with open(file_path, "rb") as f:
            return f.read()
    except:
        return None

def save_file_metadata(original_filename, saved_filename, uploader, expiry_hours, max_downloads, receiver_email, file_id):
    try:
        file_ref = db.collection('files').document(file_id)
        file_ref.set({
            'original_filename': original_filename,
            'saved_filename': saved_filename,
            'uploader': uploader,
            'upload_time': datetime.now(timezone.utc),
            'expiry_hours': expiry_hours,
            'max_downloads': max_downloads,
            'download_count': 0,
            'receiver_email': receiver_email,
            'otp_code': '',
            'otp_verified': False,
            'file_id': file_id,
        })
        return True
    except:
        return False

def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, password, role):
    try:
        user_ref = db.collection('users').document(username)
        user_ref.set({'username': username, 'password': hash_password(password), 'role': role}); return True
    except: return False

def authenticate_user(username, password):
    try:
        user_doc = db.collection('users').document(username).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            if user_data['password'] == hash_password(password): return user_data
    except: return None

def generate_otp(): return str(uuid.uuid4().int)[:6]

def send_otp_email(receiver_email, otp, file_id, filename):
    try:
        sender_email = st.secrets["email"]["sender"]
        sender_password = st.secrets["email"]["password"]
        verify_url = f"{st.secrets['base_url']}?verify={file_id}"
        subject = f"🔐 OTP for file: {filename}"
        body = f"Your OTP to download {filename} is: {otp}\n\nClick here to verify: {verify_url}"
        msg = MIMEText(body)
        msg['Subject'], msg['From'], msg['To'] = subject, sender_email, receiver_email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg); return True
    except: return False

def update_file_otp(file_id, otp):
    try:
        db.collection('files').document(file_id).update({'otp_code': otp}); return True
    except: return False

def verify_file_otp(file_id, entered_otp):
    try:
        file_ref = db.collection('files').document(file_id)
        file_doc = file_ref.get()
        if file_doc.exists and file_doc.to_dict().get('otp_code') == entered_otp:
            file_ref.update({'otp_verified': True}); return True
    except: return False

def check_download_permission(file_id):
    try:
        file_doc = db.collection('files').document(file_id).get()
        if not file_doc.exists: return False, "File does not exist."
        file_data = file_doc.to_dict()
        if not file_data.get('otp_verified', False): return False, "OTP not verified."
        upload_time = file_data['upload_time']
        if upload_time.tzinfo is None: upload_time = upload_time.replace(tzinfo=timezone.utc)
        expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
        if datetime.now(timezone.utc) > expiry_time: return False, "This file link has expired."
        if file_data['download_count'] >= file_data['max_downloads']: return False, "The maximum download limit has been reached."
        return True, file_data
    except: return False, "An error occurred."

def increment_download_count(file_id):
    try:
        doc_ref = db.collection('files').document(file_id)
        db.transaction(lambda transaction, ref: transaction.update(ref, {'download_count': firestore.Increment(1)}), doc_ref); return True
    except: return False

def get_user_files(username):
    try:
        files_ref = db.collection('files').where('uploader', '==', username).stream()
        file_list = []
        for file_doc in files_ref:
            file_data = file_doc.to_dict()
            file_data['id'] = file_doc.id; file_list.append(file_data)
        return file_list
    except: return []

def get_received_files(email):
    try:
        files_ref = db.collection('files').where('receiver_email', '==', email).stream()
        file_list = []
        for file_doc in files_ref:
            file_data = file_doc.to_dict()
            file_data['id'] = file_doc.id; file_list.append(file_data)
        return file_list
    except: return []


# --- Main App Starts Here ---
st.set_page_config(page_title="Secure File Sharing", page_icon="🔒", layout="wide")
query_params = st.query_params

# --- Verification and Download Pages Logic ---
if "verify" in query_params:
    file_id = query_params.get("verify")
    st.title("🔐 Verify OTP to Access File")
    with st.form("otp_form"):
        entered_otp = st.text_input("Enter your OTP:", type="password")
        if st.form_submit_button("Verify OTP"):
            if verify_file_otp(file_id, entered_otp):
                st.success("✅ OTP verified! You can now download the file.")
                # Since this is local, we show a download link directly
                st.page_link(f"?download={file_id}", label="➡️ Go to Download Page", icon="➡️")
            else:
                st.error("❌ Invalid OTP. Please try again.")
    st.stop()

if "download" in query_params:
    file_id = query_params.get("download")
    st.title("📥 Download File")
    can_download, result = check_download_permission(file_id)
    if can_download:
        file_data = result
        file_content = get_local_file_content(file_data['saved_filename'])
        if file_content:
            st.success(f"✅ File ready for download: {file_data['original_filename']}")
            st.download_button(
                label=f"📥 Download {file_data['original_filename']}",
                data=file_content,
                file_name=file_data['original_filename']
            )
            if 'download_link_generated' not in st.session_state or st.session_state.download_link_generated != file_id:
                increment_download_count(file_id)
                st.session_state.download_link_generated = file_id
        else:
            st.error("❌ File not found on local storage.")
    else:
        st.error(f"❌ Access Denied: {result}")
    st.stop()

# --- Main App Interface (Single-Page Structure) ---
st.title("🔒 Secure File Sharing System")

with st.sidebar:
    st.header("Navigation")
    if 'user' not in st.session_state:
        page = st.selectbox("Go to:", ["🏠 Home", "🔐 Login", "📝 Register"])
    else:
        user_role = st.session_state.user.get('role')
        if user_role == 'sender':
            page = st.selectbox("Go to:", ["📤 Upload", "📊 Dashboard", "🚪 Logout"])
        else:
            page = st.selectbox("Go to:", ["📥 My Downloads", "🚪 Logout"])

if 'user' in st.session_state:
    st.sidebar.markdown("---")
    st.sidebar.info(f"Logged in as: {st.session_state.user['username']}")

if page == "🚪 Logout":
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.success("✅ Logged out successfully!")
    st.rerun()

if page == "🏠 Home":
    st.markdown("### Welcome! Use the sidebar to log in or register.")

elif page == "🔐 Login":
    st.header("🔐 User Login")
    with st.form("login_form"):
        username = st.text_input("Username (Email):")
        password = st.text_input("Password:", type="password")
        if st.form_submit_button("Login"):
            user_data = authenticate_user(username, password)
            if user_data:
                st.session_state.user = user_data
                st.rerun()
            else:
                st.error("Invalid credentials!")

elif page == "📝 Register":
    st.header("📝 Register New User")
    with st.form("register_form"):
        new_username = st.text_input("Username (Email):", key="reg_user")
        new_password = st.text_input("Password:", type="password", key="reg_pass", help="Must be >6 characters.")
        confirm_password = st.text_input("Confirm Password:", type="password", key="reg_confirm")
        role = st.selectbox("Role:", ["sender", "receiver"])
        if st.form_submit_button("Register"):
            if new_password != confirm_password: st.error("Passwords do not match!")
            elif len(new_password) < 6: st.error("Password must be at least 6 characters!")
            elif create_user(new_username, new_password, role): st.success("User created! You can now login.")
            else: st.error("Username may already be taken!")

elif page == "📤 Upload":
    st.header("📤 Upload File")
    if 'user' in st.session_state and st.session_state.user.get('role') == 'sender':
        with st.form("upload_form", clear_on_submit=True):
            uploaded_file = st.file_uploader("Choose a file:")
            expiry_hours = st.number_input("Expiry time (hours):", 1, 168, 24)
            max_downloads = st.number_input("Max downloads:", 1, 100, 10)
            receiver_email = st.text_input("Receiver's email address:")
            if st.form_submit_button("Upload & Send"):
                if uploaded_file and receiver_email:
                    file_id = str(uuid.uuid4())
                    saved_filename = save_file_locally(uploaded_file, file_id)
                    if saved_filename and save_file_metadata(uploaded_file.name, saved_filename, st.session_state.user['username'], expiry_hours, max_downloads, receiver_email, file_id):
                        otp = generate_otp()
                        if update_file_otp(file_id, otp) and send_otp_email(receiver_email, otp, file_id, uploaded_file.name):
                            st.success("✅ File uploaded and OTP sent!")
                        else: st.error("❌ Failed to send OTP email!")
                    else: st.error("❌ Failed to save file!")
                else: st.warning("Please provide a file and a receiver's email.")
    else:
        st.error("You must be logged in as a sender to upload.")

elif page == "📊 Dashboard":
    st.header("📊 Your Uploaded Files")
    if 'user' in st.session_state and st.session_state.user.get('role') == 'sender':
        files = get_user_files(st.session_state.user['username'])
        if files:
            for file_data in files:
                with st.expander(f"📄 {file_data.get('original_filename', 'N/A')}"):
                    st.write(f"**Receiver:** {file_data.get('receiver_email')}")
                    st.write(f"**Downloads:** {file_data.get('download_count')}/{file_data.get('max_downloads')}")
                    st.code(f"{st.secrets['base_url']}?verify={file_data['id']}", language=None)
        else:
            st.info("📭 No files uploaded yet.")
    else:
        st.error("You must be logged in as a sender.")

elif page == "📥 My Downloads":
    st.header("📥 My Downloads")
    if 'user' in st.session_state and st.session_state.user.get('role') == 'receiver':
        receiver_email = st.session_state.user['username']
        files = get_received_files(receiver_email)
        if files:
            for file_data in files:
                with st.expander(f"📄 {file_data.get('original_filename', 'N/A')} from {file_data.get('uploader')}"):
                    st.write(f"**From:** {file_data.get('uploader')}")
                    st.write(f"**Expiry:** {file_data.get('expiry_hours')} hours")
                    st.page_link(f"?verify={file_data['id']}", label="➡️ Go to Download Page", icon="➡️")
    else:
        st.info("📭 You have not received any files yet.")
else:
        st.error("You must be logged in as a receiver.")