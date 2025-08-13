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
            st.error("Firebase secrets are not configured correctly. Please check your .streamlit/secrets.toml file.")
            st.stop()
    return firestore.client()

db = init_firebase()

# --- Helper Functions ---

def save_file_locally(uploaded_file, file_id):
    """Saves the uploaded file to the local 'uploads' directory."""
    try:
        # Create a unique filename to avoid conflicts
        unique_filename = f"{file_id}_{uploaded_file.name}"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return unique_filename # Return the name it was saved as
    except Exception as e:
        st.error(f"Error saving file locally: {e}")
        return None

def get_local_file_content(saved_filename):
    """Reads the file content from the local 'uploads' directory."""
    try:
        file_path = os.path.join(UPLOAD_FOLDER, saved_filename)
        with open(file_path, "rb") as f:
            return f.read()
    except Exception as e:
        st.error(f"Error reading file: {e}")
        return None

def save_file_metadata(original_filename, saved_filename, uploader, expiry_hours, max_downloads, receiver_email, file_id):
    """Saves file metadata to Firestore."""
    try:
        file_ref = db.collection('files').document(file_id)
        file_ref.set({
            'original_filename': original_filename,
            'saved_filename': saved_filename, # Store the name used for saving
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
    except Exception as e:
        st.error(f"Error saving metadata: {e}")
        return False
        
# (Paste the rest of your helper functions here: hash_password, create_user, authenticate_user, etc.)
# ...
# The functions below are assumed to be pasted from your previous complete code.
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
    # ... (paste your existing if "verify": block here) ...
    st.stop()

if "download" in query_params:
    file_id = query_params.get("download")
    st.title("📥 Download File")
    can_download, result = check_download_permission(file_id)
    if can_download:
        file_data = result
        # Read the file from the local 'uploads' folder
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

# (Paste the rest of your single-page elif blocks here for Home, Login, Register, Upload, etc.)
# For the Upload page, make sure to use the new local storage functions.

if page == "📤 Upload":
    st.header("📤 Upload File")
    if 'user' in st.session_state and st.session_state.user.get('role') == 'sender':
        with st.form("upload_form", clear_on_submit=True):
            uploaded_file = st.file_uploader("Choose a file:")
            expiry_hours = st.number_input("Expiry time (hours):", 1, 168, 24)
            max_downloads = st.number_input("Max downloads:", 1, 100, 10)
            receiver_email = st.text_input("Receiver's email address:")
            if st.form_submit_button("Upload & Send"):
                if uploaded_file and receiver_email:
                    with st.spinner("Uploading and sending..."):
                        file_id = str(uuid.uuid4())
                        # Use the new local storage function
                        saved_filename = save_file_locally(uploaded_file, file_id)
                        if saved_filename:
                            if save_file_metadata(uploaded_file.name, saved_filename, st.session_state.user['username'], expiry_hours, max_downloads, receiver_email, file_id):
                                otp = generate_otp()
                                if update_file_otp(file_id, otp):
                                    if send_otp_email(receiver_email, otp, file_id, uploaded_file.name):
                                        st.success("✅ File uploaded and OTP sent!")
                                    else: st.error("❌ Uploaded but failed to send email!")
                                else: st.error("❌ Failed to generate OTP!")
                            else: st.error("❌ Failed to save file metadata!")
                        else: st.error("❌ Failed to save file to local storage!")
                else:
                    st.warning("Please provide a file and a receiver's email.")
    else:
        st.error("You must be logged in as a sender to upload.")

# (Add your other elif blocks for Home, Login, Register, Dashboard, My Downloads here)