import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import uuid
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

# --- Cloudinary Imports and Configuration ---
import cloudinary
import cloudinary.uploader
import cloudinary.api

# This block configures Cloudinary using your secrets file
try:
    cloudinary.config(
       cloud_name = st.secrets["cloudinary"]["cloud_name"],
       api_key = st.secrets["cloudinary"]["api_key"],
       api_secret = st.secrets["cloudinary"]["api_secret"],
       secure = True
    )
except Exception as e:
    # This will show a helpful error if the secrets are not set
    st.error("Cloudinary secrets are not configured correctly. Please check your secrets.toml file.")
    st.stop()
# -----------------------------------------

@st.cache_resource
def init_firebase():
    if not firebase_admin._apps:
        try:
            # Reconstruct the credentials dictionary from individual secrets
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
            st.error("Firebase secrets are not configured correctly. Please check the [firebase] section in your secrets.")
            st.stop()

    return firestore.client()

# Initialize Firestore
db = init_firebase()
# ---------------------------------


# --- Helper Functions ---

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, password, role):
    try:
        user_ref = db.collection('users').document(username)
        user_ref.set({
            'username': username,
            'password': hash_password(password),
            'role': role
        })
        return True
    except Exception as e:
        st.error(f"Error creating user: {e}")
        return False

def authenticate_user(username, password):
    try:
        user_ref = db.collection('users').document(username)
        user_doc = user_ref.get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            if user_data['password'] == hash_password(password):
                return user_data
    except Exception as e:
        st.error(f"Authentication error: {e}")
    return None

def save_file_to_cloudinary(uploaded_file, file_id):
    """Uploads a file to Cloudinary and returns its secure URL."""
    try:
        result = cloudinary.uploader.upload(
            uploaded_file,
            public_id=file_id,
            resource_type="auto", # Allows any file type
            folder="secure_uploads/"
        )
        return result['secure_url']
    except Exception as e:
        st.error(f"Cloudinary Upload Error: {e}")
        return None

def save_file_metadata(filename, uploader, expiry_hours, max_downloads, receiver_email, file_id, download_url):
    """Saves file metadata including the Cloudinary download URL to Firestore."""
    try:
        file_ref = db.collection('files').document(file_id)
        file_ref.set({
            'filename': filename,
            'uploader': uploader,
            'upload_time': datetime.now(timezone.utc),
            'expiry_hours': expiry_hours,
            'max_downloads': max_downloads,
            'download_count': 0,
            'receiver_email': receiver_email,
            'otp_code': '',
            'otp_verified': False,
            'file_id': file_id,
            'download_url': download_url  # Storing the permanent URL from Cloudinary
        })
        return True
    except Exception as e:
        st.error(f"Error saving metadata: {e}")
        return False

def generate_otp():
    return str(uuid.uuid4().int)[:6]

def send_otp_email(receiver_email, otp, file_id, filename):
    try:
        sender_email = st.secrets["email"]["sender"]
        sender_password = st.secrets["email"]["password"]
        
        verify_url = f"https://file-sharing-ghost-of-uchiha.streamlit.app/?verify={file_id}"
        
        subject = f"🔐 OTP for file: {filename}"
        body = f"Your OTP to download {filename} is: {otp}\n\nClick here to verify: {verify_url}"
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        return True
    except Exception as e:
        st.error(f"Error sending email: {e}")
        return False

def update_file_otp(file_id, otp):
    try:
        db.collection('files').document(file_id).update({'otp_code': otp})
        return True
    except Exception as e:
        st.error(f"Error updating OTP: {e}")
        return False

def verify_file_otp(file_id, entered_otp):
    try:
        file_ref = db.collection('files').document(file_id)
        file_doc = file_ref.get()
        if file_doc.exists and file_doc.to_dict().get('otp_code') == entered_otp:
            file_ref.update({'otp_verified': True})
            return True
    except Exception as e:
        st.error(f"Error verifying OTP: {e}")
    return False

def check_download_permission(file_id):
    try:
        file_doc = db.collection('files').document(file_id).get()
        if not file_doc.exists:
            return False, "File does not exist."

        file_data = file_doc.to_dict()
        
        if not file_data.get('otp_verified', False):
            return False, "OTP not verified. Please use the link from your email to verify the OTP first."
        
        upload_time = file_data['upload_time']
        if upload_time.tzinfo is None:
             upload_time = upload_time.replace(tzinfo=timezone.utc)
        
        expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
        if datetime.now(timezone.utc) > expiry_time:
            return False, "This file link has expired."
        
        if file_data['download_count'] >= file_data['max_downloads']:
            return False, "The maximum download limit has been reached."
            
        return True, file_data
    except Exception as e:
        st.error(f"Error checking permissions: {e}")
        return False, "An error occurred while checking the file."

def increment_download_count(file_id):
    try:
        # Use a transaction for safe incrementing
        doc_ref = db.collection('files').document(file_id)
        db.transaction(lambda transaction, ref: transaction.update(ref, {'download_count': firestore.Increment(1)}), doc_ref)
        return True
    except Exception as e:
        st.error(f"Error updating download count: {e}")
        return False

def get_user_files(username):
    try:
        files_ref = db.collection('files').where('uploader', '==', username).stream()
        file_list = []
        for file_doc in files_ref:
            file_data = file_doc.to_dict()
            file_data['id'] = file_doc.id
            upload_time = file_data['upload_time']
            if upload_time.tzinfo is None:
                 upload_time = upload_time.replace(tzinfo=timezone.utc)
            expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
            file_data['expired'] = datetime.now(timezone.utc) > expiry_time
            file_list.append(file_data)
        return file_list
    except Exception as e:
        st.error(f"Error fetching files: {e}")
        return []

def get_received_files(email):
    """Fetches all files sent to a specific receiver's email."""
    try:
        # Query the 'files' collection where the receiver_email matches
        files_ref = db.collection('files').where('receiver_email', '==', email).stream()
        file_list = []
        for file_doc in files_ref:
            file_data = file_doc.to_dict()
            file_data['id'] = file_doc.id
            
            # Check if expired
            upload_time = file_data['upload_time']
            if upload_time.tzinfo is None:
                 upload_time = upload_time.replace(tzinfo=timezone.utc)
            expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
            file_data['expired'] = datetime.now(timezone.utc) > expiry_time
            
            file_list.append(file_data)
        return file_list
    except Exception as e:
        st.error(f"Error fetching received files: {e}")
        return []
# --- Main App Starts Here ---
st.set_page_config(page_title="Secure File Sharing", page_icon="🔒", layout="wide")

query_params = st.query_params

# --- Verification and Download Pages Logic ---
if "verify" in query_params:
    file_id = query_params["verify"][0]
    st.title("🔐 Verify OTP to Access File")
    with st.form("otp_form"):
        entered_otp = st.text_input("Enter your OTP:", type="password")
        if st.form_submit_button("Verify OTP"):
            if verify_file_otp(file_id, entered_otp):
                st.success("✅ OTP verified! Redirecting to download...")
                st.balloons()
                st.markdown(f'<meta http-equiv="refresh" content="2;url=?download={file_id}">', unsafe_allow_html=True)
            else:
                st.error("❌ Invalid OTP. Please try again.")
    st.stop()

if "download" in query_params:
    file_id = query_params["download"][0]
    st.title("📥 Download File")
    can_download, result = check_download_permission(file_id)
    
    if can_download:
        file_data = result
        download_url = file_data.get('download_url')
        if download_url:
            st.success("✅ File ready! Click the link below to download.")
            st.markdown(f"## [📥 Download {file_data['filename']}]({download_url})")
            if 'download_link_generated' not in st.session_state or st.session_state.download_link_generated != file_id:
                increment_download_count(file_id)
                st.session_state.download_link_generated = file_id
        else:
            st.error("❌ Download link not found for this file.")
    else:
        st.error(f"❌ Access Denied: {result}")
    st.stop()

# --- Main App Interface (Sidebar and Pages) ---
st.title("🔒 Secure File Sharing System")


# DELETE YOUR OLD SIDEBAR BLOCK AND REPLACE IT WITH THIS
with st.sidebar:
    st.header("Navigation")
    if 'user' not in st.session_state:
        page = st.selectbox("Go to:", ["🏠 Home", "🔐 Login", "📝 Register"])
    else:
        user_role = st.session_state.user.get('role')
        if user_role == 'sender':
            page = st.selectbox("Go to:", ["📤 Upload", "📊 Dashboard", "🚪 Logout"])
        else:  # This is the new logic for the 'receiver' role
            page = st.selectbox("Go to:", ["📥 My Downloads", "🚪 Logout"])

if 'user' in st.session_state and page == "🚪 Logout":
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.success("✅ Logged out successfully!")
    st.rerun()

if page == "🏠 Home":
    st.markdown("## Welcome to the Secure File Sharing System...")

elif page == "🔐 Login":
    st.header("🔐 User Login")
    with st.form("login_form"):
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")
        if st.form_submit_button("Login"):
            user_data = authenticate_user(username, password)
            if user_data:
                st.session_state.user = user_data
                st.rerun()
            else:
                st.error("❌ Invalid credentials!")

elif page == "📝 Register":
    st.header("📝 Register New User")
    with st.form("register_form"):
        new_username = st.text_input("Username:")
        new_password = st.text_input("Password:", type="password", help="Must be at least 6 characters.")
        confirm_password = st.text_input("Confirm Password:", type="password")
        role = st.selectbox("Role:", ["sender", "receiver"])
        if st.form_submit_button("Register"):
            if new_password != confirm_password:
                st.error("❌ Passwords do not match!")
            elif len(new_password) < 6:
                st.error("❌ Password must be at least 6 characters!")
            elif create_user(new_username, new_password, role):
                st.success("✅ User created successfully! You can now login.")
            else:
                st.error("❌ Username may already be taken!")

elif 'user' in st.session_state and page == "📥 My Downloads":
    st.header("📥 My Downloads")
    st.info("These are the files that have been sent to your email address.")

    # The receiver's username is their email address
    receiver_email = st.session_state.user['username']
    files = get_received_files(receiver_email)

    if files:
        for file_data in files:
            with st.expander(f"📄 {file_data['filename']} from {file_data['uploader']}"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**From:** {file_data['uploader']}")
                    st.write(f"**Expiry:** {file_data['expiry_hours']} hours")
                
                with col2:
                    st.write(f"**Downloads:** {file_data['download_count']}/{file_data['max_downloads']}")
                    status = "❌ Expired" if file_data['expired'] else "✅ Active"
                    st.write(f"**Status:** {status}")
                
                with col3:
                    if not file_data['expired']:
                        st.write("**Action:**")
                        verify_url = f"https://file-sharing-ghost-of-uchiha.streamlit.app/?verify={file_data['id']}"
                        # Provide a direct link to the verification page
                        st.link_button("➡️ Go to Download Page", verify_url)
                        st.code(verify_url)
                    else:
                        st.write("**Action:**")
                        st.error("Link Expired")
    else:
        st.info("📭 You have not received any files yet.")

elif 'user' in st.session_state and page == "📤 Upload":
    st.header("📤 Upload File")
    with st.form("upload_form", clear_on_submit=True):
        uploaded_file = st.file_uploader("Choose a file:")
        expiry_hours = st.number_input("Expiry time (hours):", 1, 168, 24)
        max_downloads = st.number_input("Max downloads:", 1, 100, 10)
        receiver_email = st.text_input("Receiver's email address:")
        if st.form_submit_button("Upload & Send"):
            if uploaded_file and receiver_email:
                with st.spinner("Uploading, securing, and sending..."):
                    file_id = str(uuid.uuid4())
                    download_url = save_file_to_cloudinary(uploaded_file, file_id)
                    if download_url:
                        if save_file_metadata(uploaded_file.name, st.session_state.user['username'], expiry_hours, max_downloads, receiver_email, file_id, download_url):
                            otp = generate_otp()
                            if update_file_otp(file_id, otp):
                                if send_otp_email(receiver_email, otp, file_id, uploaded_file.name):
                                    st.success("✅ File uploaded and OTP sent!")
                                else:
                                    st.error("❌ Uploaded but failed to send email!")
                            else:
                                st.error("❌ Failed to generate OTP!")
                        else:
                            st.error("❌ Failed to save file metadata!")
                    else:
                        st.error("❌ Failed to upload file to storage!")
            else:
                st.warning("Please provide a file and a receiver's email.")

elif 'user' in st.session_state and page == "📊 Dashboard":
    st.header("📊 Your Uploaded Files")
    files = get_user_files(st.session_state.user['username'])
    if files:
        for file_data in files:
            with st.expander(f"📄 {file_data['filename']}"):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Receiver:** {file_data['receiver_email']}")
                    st.write(f"**Expiry:** {file_data['expiry_hours']} hours")
                with col2:
                    st.write(f"**Downloads:** {file_data['download_count']}/{file_data['max_downloads']}")
                    status = "❌ Expired" if file_data['expired'] else "✅ Active"
                    st.write(f"**Status:** {status}")
                with col3:
                    st.write("**Verify URL:**")
                    verify_url = f"https://file-sharing-ghost-of-uchiha.streamlit.app/?verify={file_data['id']}"
                    st.code(verify_url, language=None)
    else:
        st.info("📭 No files uploaded yet.")

if 'user' in st.session_state:
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"👤 **Logged in as:** {st.session_state.user['username']}")
    st.sidebar.markdown(f"🏷️ **Role:** {st.session_state.user['role']}")