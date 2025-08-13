import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import uuid
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from datetime import timezone
# At the top of app.py
import cloudinary
import cloudinary.uploader
import cloudinary.api

# Add this configuration block right after your imports
cloudinary.config(
   cloud_name = st.secrets["cloudinary"]["cloud_name"],
   api_key = st.secrets["cloudinary"]["api_key"],
   api_secret = st.secrets["cloudinary"]["api_secret"],
   secure = True
)

# Initialize Firebase (Firestore only, no storage)
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

# File storage in session state (alternative to Firebase Storage)
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = {}

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

def save_file_in_memory(uploaded_file, file_id):
    """Store file content in session state instead of Firebase Storage"""
    file_content = uploaded_file.read()
    st.session_state.uploaded_files[file_id] = {
        'content': file_content,
        'name': uploaded_file.name,
        'type': uploaded_file.type
    }
    return True

def get_file_from_memory(file_id):
    """Retrieve file content from session state"""
    return st.session_state.uploaded_files.get(file_id)

def save_file_metadata(filename, uploader, expiry_hours, max_downloads, receiver_email, file_id):
    try:
        file_ref = db.collection('files').document(file_id)
        file_ref.set({
            'filename': filename,
            'uploader': uploader,
            'upload_time': datetime.now(),
            'expiry_hours': expiry_hours,
            'max_downloads': max_downloads,
            'download_count': 0,
            'receiver_email': receiver_email,
            'otp_code': '',
            'otp_verified': False,
            'file_id': file_id
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
        body = f"""
        Hello!
        
        You have received a secure file: {filename}
        
        🔑 Your OTP: {otp}
        
        Click here to verify and download: {verify_url}
        
        This link will expire based on the sender's settings.
        
        Best regards,
        Secure File Sharing System
        """
        
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = receiver_email
        
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        st.error(f"Error sending email: {e}")
        return False

def update_file_otp(file_id, otp):
    try:
        file_ref = db.collection('files').document(file_id)
        file_ref.update({'otp_code': otp})
        return True
    except Exception as e:
        st.error(f"Error updating OTP: {e}")
        return False

def verify_file_otp(file_id, entered_otp):
    try:
        file_ref = db.collection('files').document(file_id)
        file_doc = file_ref.get()
        if file_doc.exists:
            file_data = file_doc.to_dict()
            if file_data['otp_code'] == entered_otp:
                file_ref.update({'otp_verified': True})
                return True
    except Exception as e:
        st.error(f"Error verifying OTP: {e}")
    return False

def check_download_permission(file_id):
    try:
        file_ref = db.collection('files').document(file_id)
        file_doc = file_ref.get()
        if file_doc.exists:
            file_data = file_doc.to_dict()
            
            # Check if OTP is verified
            if not file_data.get('otp_verified', False):
                return False, "OTP not verified"
            
            # Check expiry time
            upload_time = file_data['upload_time']
            if isinstance(upload_time, str):
                upload_time = datetime.fromisoformat(upload_time).replace(tzinfo=timezone.utc)
            expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
            
            if datetime.now(timezone.utc) > expiry_time:
                return False, "File has expired"
            
            # Check download count
            if file_data['download_count'] >= file_data['max_downloads']:
                return False, "Download limit reached"
            
            return True, file_data
    except Exception as e:
        st.error(f"Error checking permissions: {e}")
    return False, "Error checking file"

def increment_download_count(file_id):
    try:
        file_ref = db.collection('files').document(file_id)
        file_doc = file_ref.get()
        if file_doc.exists:
            current_count = file_doc.to_dict().get('download_count', 0)
            file_ref.update({'download_count': current_count + 1})
            return True
    except Exception as e:
        st.error(f"Error updating download count: {e}")
    return False

def get_user_files(username):
    try:
        files_ref = db.collection('files').where('uploader', '==', username)
        files = files_ref.stream()
        file_list = []
        for file_doc in files:
            file_data = file_doc.to_dict()
            file_data['id'] = file_doc.id
            
            # Check if expired
            upload_time = file_data['upload_time']
            if isinstance(upload_time, str):
                upload_time = datetime.fromisoformat(upload_time)
            expiry_time = upload_time + timedelta(hours=file_data['expiry_hours'])
            file_data['expired'] = datetime.now() > expiry_time
            
            file_list.append(file_data)
        return file_list
    except Exception as e:
        st.error(f"Error fetching files: {e}")
        return []

# Streamlit App Configuration
st.set_page_config(
    page_title="Secure File Sharing",
    page_icon="🔒",
    layout="wide"
)

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
# Handle URL parameters for verify and download
query_params = st.query_params

# Handle verification flow
if "verify" in query_params:
    file_id = query_params["verify"][0]
    st.title("🔐 Verify OTP to Access File")
    
    with st.form("otp_form"):
        entered_otp = st.text_input("Enter your OTP:", type="password")
        submit_otp = st.form_submit_button("Verify OTP")
        
        if submit_otp and entered_otp:
            if verify_file_otp(file_id, entered_otp):
                st.success("✅ OTP verified! Redirecting to download...")
                st.markdown(f'<meta http-equiv="refresh" content="2;url=?download={file_id}">', unsafe_allow_html=True)
                st.stop()
            else:
                st.error("❌ Invalid OTP. Please try again.")
    st.stop()

# Handle download flow
if "download" in query_params:
    file_id = query_params["download"][0]
    st.title("📥 Download File")
    
    can_download, result = check_download_permission(file_id)
    
    if can_download:
        file_data = result
        file_content = get_file_from_memory(file_id)
        
        if file_content:
            st.success(f"✅ File ready for download: {file_data['filename']}")
            
            # Create download button
            st.download_button(
                label=f"📥 Download {file_data['filename']}",
                data=file_content['content'],
                file_name=file_data['filename'],
                mime=file_content['type']
            )
            
            # Update download count
            if increment_download_count(file_id):
                st.info("Download count updated.")
        else:
            st.error("❌ File content not found. File may have been removed from memory.")
    else:
        st.error(f"❌ {result}")
    
    st.stop()

# Main App Interface
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

# Handle logout
if 'user' in st.session_state and page == "🚪 Logout":
    del st.session_state.user
    st.success("✅ Logged out successfully!")
    st.rerun()


# Home page
if page == "🏠 Home":
    st.markdown("""
    ## Welcome to Secure File Sharing System
    
    ### Features:
    - 🔐 **OTP-based security** - Files require OTP verification
    - ⏰ **Time-based expiry** - Set custom expiry hours
    - 📊 **Download limits** - Control maximum downloads
    - 📧 **Email notifications** - Automatic OTP delivery
    - 👥 **Role-based access** - Sender and receiver roles
    - 📈 **Admin dashboard** - Track all uploads and downloads
    
    ### How it works:
    1. **Sender** uploads file with settings
    2. **Receiver** gets email with OTP
    3. **Verification** required before download
    4. **Tracking** of all activities
    """)

# Login page
elif page == "🔐 Login":
    st.header("🔐 Login")
    
    with st.form("login_form"):
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")
        login_button = st.form_submit_button("Login")
        
        if login_button:
            user_data = authenticate_user(username, password)
            if user_data:
                st.session_state.user = user_data
                st.success(f"✅ Welcome back, {username}!")
                st.rerun()

            else:
                st.error("❌ Invalid credentials!")

# Register page
elif page == "📝 Register":
    st.header("📝 Register New User")
    
    with st.form("register_form"):
        new_username = st.text_input("Username:")
        new_password = st.text_input("Password:", type="password")
        confirm_password = st.text_input("Confirm Password:", type="password")
        role = st.selectbox("Role:", ["sender", "receiver"])
        register_button = st.form_submit_button("Register")
        
        if register_button:
            if new_password != confirm_password:
                st.error("❌ Passwords don't match!")
            elif len(new_password) < 6:
                st.error("❌ Password must be at least 6 characters!")
            else:
                if create_user(new_username, new_password, role):
                    st.success("✅ User created successfully! You can now login.")
                else:
                    st.error("❌ Username already exists!")

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

# Upload page (sender only)
elif 'user' in st.session_state and page == "📤 Upload":
    if st.session_state.user['role'] != 'sender':
        st.error("❌ Only senders can upload files!")
    else:
        st.header("📤 Upload File")
        
        with st.form("upload_form"):
            uploaded_file = st.file_uploader("Choose a file:")
            expiry_hours = st.number_input("Expiry time (hours):", min_value=1, max_value=168, value=24)
            max_downloads = st.number_input("Max downloads:", min_value=1, max_value=100, value=10)
            receiver_email = st.text_input("Receiver email:")
            upload_button = st.form_submit_button("Upload & Send")
            
            if upload_button and uploaded_file and receiver_email:
                file_id = str(uuid.uuid4())
                
                # Save file in memory
                if save_file_in_memory(uploaded_file, file_id):
                    # Save metadata
                    if save_file_metadata(
                        uploaded_file.name,
                        st.session_state.user['username'],
                        expiry_hours,
                        max_downloads,
                        receiver_email,
                        file_id
                    ):
                        # Generate and send OTP
                        otp = generate_otp()
                        if update_file_otp(file_id, otp):
                            if send_otp_email(receiver_email, otp, file_id, uploaded_file.name):
                                st.success("✅ File uploaded and OTP sent successfully!")
                                st.info(f"📧 OTP sent to: {receiver_email}")
                                st.info(f"🔗 Verify URL: {st.secrets['base_url']}?verify={file_id}")
                            else:
                                st.error("❌ File uploaded but failed to send email!")
                        else:
                            st.error("❌ Failed to generate OTP!")
                    else:
                        st.error("❌ Failed to save file metadata!")
                else:
                    st.error("❌ Failed to upload file!")

# Admin Dashboard (sender only)
elif 'user' in st.session_state and page == "📊 Admin Dashboard":
    if st.session_state.user['role'] != 'sender':
        st.error("❌ Only senders can access admin dashboard!")
    else:
        st.header("📊 Admin Dashboard")
        
        files = get_user_files(st.session_state.user['username'])
        
        if files:
            for file_data in files:
                with st.expander(f"📄 {file_data['filename']}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Upload time:** {file_data['upload_time']}")
                        st.write(f"**Expiry:** {file_data['expiry_hours']} hours")
                        
                    with col2:
                        st.write(f"**Downloads:** {file_data['download_count']}/{file_data['max_downloads']}")
                        status = "❌ Expired" if file_data['expired'] else "✅ Active"
                        st.write(f"**Status:** {status}")
                        
                    with col3:
                        st.write(f"**Receiver:** {file_data['receiver_email']}")
                        verify_url = f"https://file-sharing-ghost-of-uchiha.streamlit.app/?verify={file_data['id']}"
                        st.code(verify_url)
        else:
            st.info("📭 No files uploaded yet.")

# Show current user info
if 'user' in st.session_state:
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"👤 **Logged in as:** {st.session_state.user['username']}")
    st.sidebar.markdown(f"🏷️ **Role:** {st.session_state.user['role']}")