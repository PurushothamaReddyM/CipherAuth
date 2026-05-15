# Project 05 : Secure Multi-Factor Authentication using TOTP + SHA-512 + AES-256 + Biometric Verification

import streamlit as st
import hashlib
import json
import os
import time
import pyotp
import smtplib
import base64
from email.mime.text import MIMEText
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import pbkdf2_hmac
from streamlit_lottie import st_lottie
import requests
from streamlit_autorefresh import st_autorefresh


import cv2
import face_recognition
import numpy as np

# Function to load animation from a URL
def load_lottieurl(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# Function to send OTP email
def send_otp_email(receiver_email, final_otp):
    sender_email = "reddypurushothama257@gmail.com"
    app_password = "oeqqhtscejihifnt"

    msg = MIMEText(f"Your Final OTP is: {final_otp}")
    msg["Subject"] = "Your OTP Verification Code"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, app_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

# === Data configuration ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session states ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "generated_otp" not in st.session_state:
    st.session_state.generated_otp = None
if "otp_verified" not in st.session_state:
    st.session_state.otp_verified = False
if "otp_time" not in st.session_state:
    st.session_state.otp_time = None
if "logs" not in st.session_state:
    st.session_state.logs = []
if "otp_attempts" not in st.session_state:
    st.session_state.otp_attempts = 0

# ================= ADD THIS IN SESSION STATE =================
if "auth_step" not in st.session_state:
    st.session_state.auth_step = "password"

if "temp_user" not in st.session_state:
    st.session_state.temp_user = None

# === Load/Save data functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# === AES-256 Key generation ===
def generate_key(passkey):
    return pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)

# === Password hashing ===
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# === AES-256 Encrypt function ===
def encrypt_text(text, key):
    key = generate_key(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

# === AES-256 Decrypt function ===
def decrypt_text(encrypted_text, key):
    try:
        key = generate_key(key)
        raw = base64.b64decode(encrypted_text)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
    except Exception:
        return None
# ================= AES 1 ROUND DEBUG =================

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
def print_state(state):
    return "\n".join(" ".join(f"{b:02x}" for b in row) for row in state)

def sub_bytes(state):
    return [[SBOX[b] for b in row] for row in state]

def shift_rows(state):
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

def mix_columns(state):
    new = [[0]*4 for _ in range(4)]
    for j in range(4):
        a = [state[i][j] for i in range(4)]
        new[0][j] = xtime(a[0]) ^ xtime(a[1]) ^ a[1] ^ a[2] ^ a[3]
        new[1][j] = a[0] ^ xtime(a[1]) ^ xtime(a[2]) ^ a[2] ^ a[3]
        new[2][j] = a[0] ^ a[1] ^ xtime(a[2]) ^ xtime(a[3]) ^ a[3]
        new[3][j] = xtime(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xtime(a[3])
    return new

def add_round_key(state, key_bytes):
    k = 0
    for j in range(4):
        for i in range(4):
            state[i][j] ^= key_bytes[k]
            k += 1
    return state

def aes_one_round(block_bytes, key_bytes):
    state = [[block_bytes[r + 4*c] for c in range(4)] for r in range(4)]

    outputs = []

    outputs.append(("Initial", print_state(state)))

    state = sub_bytes(state)
    outputs.append(("After SubBytes", print_state(state)))

    state = shift_rows(state)
    outputs.append(("After ShiftRows", print_state(state)))

    state = mix_columns(state)
    outputs.append(("After MixColumns", print_state(state)))

    state = add_round_key(state, key_bytes[:16])
    outputs.append(("After AddRoundKey", print_state(state)))

    return outputs

# === Load stored data ===
stored_data = load_data()

# === Sidebar Animation ===
lottie_lock = load_lottieurl("https://lottie.host/f9a74777-b064-4531-b7ea-b0793580932b/TBvPZE1dn3.json")

with st.sidebar:
    st.markdown("<h3 style='text-align: center;'>📌 Navigation</h3>", unsafe_allow_html=True)
    if lottie_lock:
        st_lottie(lottie_lock, height=180, key="lock_animation")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "🔢 Verify OTP", "💾 Store Data", "📂 Retrieve Data", "📊 Logs"]
choice = st.sidebar.selectbox("Select Page", menu)

# === Main Title ===
st.title("Secure Multi-Factor Authentication (Password, OTP, Biometric) using TOTP, SHA-512, AES-256 and Biometric Verification 🔐")

# === Home Page ===
if choice == "🏠 Home":
    st.subheader("Welcome To Secure Multi-Factor Authentication System")
    st.markdown("""
    - 📷 Biometric verification before OTP generation 
    - 🔢 TOTP and SHA-512 combined for OTP generation  
    - 📧 Combined OTP sent through email for verification
    - 🚫 Lockout after failed login attempts  
    - 🔒 OTP encrypted internally before validation  
    - 🔐 AES-256 encryption for secure data protection  
    - 💾 Secure local encrypted storage  
    """)

# === Register Page ===
elif choice == "📝 Register":
    st.subheader("Register New User 📝")

    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    # ✅ FACE CAPTURE ADDED
    st.info("📸 Capture 3 images for better accuracy")
    
    st.markdown("""
    1️⃣ Look straight
    2️⃣ Slightly turn LEFT
    3️⃣ Slightly turn RIGHT
    """)
    face1 = st.camera_input("Capture Face - Front")
    face2 = st.camera_input("Capture Face - Left")
    face3 = st.camera_input("Capture Face - Right")

    if st.button("Register"):
        valid_faces = [f for f in [face1, face2, face3] if f is not None]
        if username and password and len(valid_faces) >= 2:
            if username in stored_data:
                st.warning("⚠️ User already exists")
            else:
                encodings_list = []
                
                for face_input in [face1, face2, face3]:
                    if face_input is None:
                        continue
                    
                    image = face_recognition.load_image_file(face_input)
                    face_locations = face_recognition.face_locations(image)
                    
                    if len(face_locations) == 0:
                        continue
                    
                    if len(face_locations) > 1:
                        st.error("❌ Multiple faces detected during registration")
                        st.stop()
                        
                    enc = face_recognition.face_encodings(image, face_locations)[0]
                    encodings_list.append(enc)
                    
                # ❌ No valid face
                if len(encodings_list) == 0:
                    st.error("❌ No valid face detected. Try again.")
                    st.stop()
                    
                # ✅ Average encoding
                avg_encoding = np.mean(encodings_list, axis=0)
                
                # ✅ STORE THIS
                stored_data[username] = {
                    "password": hash_password(password),
                    "secret": pyotp.random_base32(),
                    "face": avg_encoding.tolist(),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# === Login Page ===
elif choice == "🔑 Login":
    st.subheader("User Login 🔑")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many failed attempts. Wait {remaining} seconds.")
        st.stop()

    # ================= STEP 1: PASSWORD =================
    if "auth_step" not in st.session_state:
        st.session_state.auth_step = "password"

    if "temp_user" not in st.session_state:
        st.session_state.temp_user = None

    if st.session_state.auth_step == "password":

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Next → Face Verification"):

            if username in stored_data and stored_data[username]["password"] == hash_password(password):

                st.session_state.temp_user = username
                st.session_state.auth_step = "face"
                st.session_state.temp_password = password
                st.success("✅ Password Verified")
                st.rerun()

            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid Credentials! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🚫 Locked for 60 seconds")
                    st.stop()
        
    # ================= STEP 2: FACE + OTP =================
    elif st.session_state.auth_step == "face":

        username = st.session_state.temp_user
        

        st.markdown("### Face Verification")

        email = st.text_input("Enter Email")
        
        

        st.info("📷 Capture your face")
        
        face_input = st.camera_input("Verify Face")

        if st.button("Verify Face & Send OTP"):

            import re
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                st.error("❌ Enter a valid email address")
                st.stop()

            if username in stored_data:

                # ✅ FACE CHECK START (UNCHANGED)
                if face_input is None:
                    st.error("❌ Please capture your face")
                    st.stop()

                if "face" not in stored_data[username]:
                    st.error("❌ No face registered for this user")
                    st.stop()

                unknown_image = face_recognition.load_image_file(face_input)
                face_locations = face_recognition.face_locations(unknown_image)
                
                if len(face_locations) == 0:
                    st.error("❌ No face detected")
                    st.stop()
                    
                if len(face_locations) > 1:
                    st.error("❌ Multiple faces detected")
                    st.stop()
                    
                avg_encoding = face_recognition.face_encodings(unknown_image, face_locations)[0]
                
                stored_encoding = np.array(stored_data[username]["face"])

                

                match = face_recognition.compare_faces([stored_encoding], avg_encoding)
                distance = face_recognition.face_distance([stored_encoding], avg_encoding)[0]
                confidence = max(0, min(1, 1 - distance))
                st.progress(confidence)
                st.write(f"Confidence: {confidence*100:.2f}%")

                if not match[0] or distance > 0.38:
                    st.error(f"❌ Face not matched (distance: {distance:.2f})")
                    st.stop()

                st.success(f"✅ Face verified (distance: {distance:.2f})")
                log = {
                    "user": username,
                    "action": "login_success",
                    "time": time.time()
                }
                
                
                    
                st.session_state.logs.append(log)
                # ✅ FACE CHECK END

                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = 0

                secret = stored_data[username]["secret"]
                current_time = int(time.time())
                st.session_state.otp_debug = {
                    "time": current_time,
                    "secret": secret,
                    "password_plain": st.session_state.temp_password,
                    "password_hash": stored_data[username]["password"]
                }
                # TOTP
                totp = pyotp.TOTP(secret)
                otp1 = int(totp.at(current_time))
                # SHA-512
                sha_input = secret + str(current_time)
                sha_hash = hashlib.sha512(sha_input.encode()).hexdigest()

                otp2 = int(sha_hash[:8], 16) % 900000

                final_otp = str((otp1 + otp2) % 900000).zfill(6)

                encrypted_final_otp = encrypt_text(final_otp, "secure_internal_otp_key_2026")

                st.session_state.generated_otp = encrypted_final_otp
                st.session_state.otp_attempts = 0
                st.session_state.otp_verified = False
                st.session_state.otp_time = time.time()
                st.session_state.user_email = email
                send_otp_email(email, final_otp)
                st.session_state.expiry_shown = False
                st.session_state.stop_timer = False

                st.success("📧 OTP Sent Successfully")
                
                st.success("👉 Go to OTP Verification page")
                st.session_state.auth_step = "password"
                st.session_state.temp_user = None
                st.session_state.temp_password = None
            else:
                st.error("❌ Session expired. Restart login.")
                
# === OTP Verification Page ===
elif choice == "🔢 Verify OTP":
    
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("Verify OTP 🔢")

        if "otp_attempts" not in st.session_state:
            st.session_state.otp_attempts = 0

        entered_otp = st.text_input("Enter Final OTP")

        if st.button("Verify OTP"):

            
            
            # ✅ BLOCK AFTER 3 ATTEMPTS
            if st.session_state.otp_attempts >= 3:
                st.error("🚫 Too many attempts. Please login again.")
                st.stop()

            current_time = time.time()

            stored_otp = decrypt_text(st.session_state.generated_otp, "secure_internal_otp_key_2026")

            if current_time - st.session_state.otp_time > 60:
                st.error("❌ OTP Expired")
                
            elif entered_otp == stored_otp:
                st.session_state.otp_verified = True
                st.session_state.otp_attempts = 0 
                st.success("✅ OTP Verified Successfully!")
            else:
                st.session_state.otp_attempts += 1
                attempts_left = 3 - st.session_state.otp_attempts
                st.error("❌ Invalid OTP")
                st.warning(f"Attempts left: {attempts_left}")
        
        if st.session_state.otp_time and time.time() - st.session_state.otp_time > 60:  
            st.warning("🔄 OTP expired. You can request a new one.")
            if st.button("🔄 Resend OTP"):
                    username = st.session_state.authenticated_user
                    
                    if username in stored_data:
                        secret = stored_data[username]["secret"]
                        current_time = int(time.time())
                        
                        totp = pyotp.TOTP(secret)
                        otp1 = int(totp.at(current_time))
                        
                        sha_input = secret + str(current_time)
                        sha_hash = hashlib.sha512(sha_input.encode()).hexdigest()
                        otp2 = int(sha_hash[:8], 16) % 900000
                        
                        final_otp = str((otp1 + otp2) % 900000).zfill(6)
                
                        encrypted_final_otp = encrypt_text(final_otp, "secure_internal_otp_key_2026")
                
                        st.session_state.generated_otp = encrypted_final_otp
                        st.session_state.otp_time = time.time()
                        st.session_state.otp_attempts = 0
                        st.session_state.otp_verified = False
                
                        # 📧 SEND EMAIL (IMPORTANT)
                        send_otp_email(st.session_state.user_email, final_otp)
                        st.success("📧 New OTP sent successfully!")

                
        if st.session_state.otp_verified:
            data = st.session_state.get("otp_debug")
            if not data:
                st.error("No debug data available")
                st.stop()
            current_time = data["time"]       
            secret = data["secret"]           
            password = data.get("password_plain", "Not Available")
            password_hash = data["password_hash"]
            
            with st.expander("🔍 View OTP Generation Process"):
                st.markdown("### 🔐 Step 1: Password & Hash")
                st.write(f"Password: {password}")
                st.write("PBKDF2 (SHA-256 + Salt + 100000 iterations)")
                st.code(password_hash[:60] + "...")
                
                st.markdown("### 🔑 Step 2: Secret Key")
                st.code(secret)
                
                st.markdown("### ⏱ Step 3: Time")
                time_step = current_time // 30
                st.write(f"Unix Time: {current_time}")
                st.write(f"Time Step (T/30): {time_step}")
                
                import hmac
                
                st.markdown("### 🔍 Step 4: Time → Bytes")
                time_bytes = time_step.to_bytes(8, 'big')
                st.code(time_bytes.hex())
                
                st.markdown("### 🔐 Step 5: Secret → Bytes")
                decoded_key = base64.b32decode(secret, casefold=True)
                st.write("Length:", len(decoded_key))
                st.code(decoded_key.hex())
                
                st.markdown("### 🔐 Step 6: HMAC-SHA1")
                hmac_hash = hmac.new(decoded_key, time_bytes, hashlib.sha1).digest()
                st.code(hmac_hash.hex())
                
                st.markdown("### 🔢 Step 7: Offset")
                offset = hmac_hash[-1] & 0x0F
                st.write(offset)
                
                st.markdown("### 🔢 Step 8: Selected 4 Bytes")
                selected_bytes = hmac_hash[offset:offset+4]
                st.code(selected_bytes.hex())
                
                st.markdown("### 🔢 Step 9: Integer Conversion")
                code_int = int.from_bytes(selected_bytes, 'big') & 0x7FFFFFFF
                st.write(code_int)
                
                st.markdown("### 🔢 Step 10: Final TOTP")
                otp_calc = code_int % 1000000
                st.metric("TOTP", str(otp_calc).zfill(6))
                
                
                    
                st.markdown("### 🔐 Step 11: SHA-512 OTP Generation")
                
                st.markdown("### 🔹 Input Creation")
                
                sha_input = secret + str(current_time)
                st.write(f"Secret Key: {secret}")
                st.write(f"Unix Time: {current_time}")
                st.code(sha_input)
                
                st.markdown("### 🔹 SHA-512 Hash")
                
                sha_hash = hashlib.sha512(sha_input.encode()).hexdigest()
                st.code(sha_hash)
                
                st.markdown("### 🔹 Selected Characters (First 8 Hex)")
                
                selected_hex = sha_hash[:8]
                st.code(selected_hex)
                
                st.markdown("### 🔹 Hex → Integer Conversion")
                
                sha_int = int(selected_hex, 16)
                st.write(f"Integer Value: {sha_int}")
                
                st.markdown("### 🔹 Modulo Operation")
                otp2 = sha_int % 900000
                
                st.write(f"{sha_int} % 900000 = {otp2}")
                
                st.markdown("### 🔹 Final SHA OTP")
                st.metric("SHA OTP", str(otp2).zfill(6))                         
                
                st.markdown("### 🔗 Step 12: Final OTP Generation")
                
                st.write(f"TOTP: {str(otp_calc).zfill(6)}")
                st.write(f"SHA OTP: {str(otp2).zfill(6)}")
                
                final_otp = str((otp_calc + otp2) % 900000).zfill(6)
                
                st.write("Formula: (TOTP + SHA OTP) % 900000")
                
                st.metric("Final OTP", final_otp)
                
                st.markdown("### 🔒 Step 13: AES-256 Encryption")
                
                from hashlib import pbkdf2_hmac
                
                passkey = "secure_internal_otp_key_2026"
                SALT = b"secure_salt_value"
                
                st.markdown("### 🔹 Key Derivation (PBKDF2)")
                
                aes_key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000, dklen=32)
                
                st.write("Passkey:", passkey)
                st.code(aes_key.hex())
                
                st.markdown("### 🔹 OTP → Bytes")
                
                otp_bytes = final_otp.encode()
                st.code(str(otp_bytes))
                
                st.markdown("### 🔹 Padding (PKCS7)")
                
                padded = pad(otp_bytes, AES.block_size)
                st.code(str(padded))
                
                st.markdown("### 🔹 IV Generation")
                
                cipher = AES.new(aes_key, AES.MODE_CBC)
                iv = cipher.iv
                
                st.code(iv.hex())
                
                st.markdown("### 🔹 CBC First Step (Concept)")
                st.markdown("### 🔢 IV ⊕ Block Calculation")
                st.write("Padded Block (Hex):")
                st.code(padded[:16].hex())
                st.write("IV (Hex):")
                st.code(iv.hex())
                xor_block = bytes([padded[i] ^ iv[i] for i in range(16)])
                st.write("IV ⊕ Block (Result):")
                st.code(xor_block.hex())
                st.write("First Block = OTP ⊕ IV (before encryption)")

                # ================= SHOW 1 ROUND =================
                st.markdown("### 🔁 AES Round 1 (Full Numeric)")
                # XOR with IV (REAL CBC FIRST STEP)
                block = xor_block
                key16 = aes_key[:16]       # first round key (simplified)
                
                round_steps = aes_one_round(block, key16)
                for step, value in round_steps:
                    st.write(step)
                    st.code(value)
                
                st.markdown("### 🔹 AES Encryption")
                
                ct_bytes = cipher.encrypt(padded)
                st.code(ct_bytes.hex())
                
                st.markdown("### 🔹 Combine IV + Ciphertext")
                
                combined = iv + ct_bytes
                st.code(combined.hex())
                
                st.markdown("### 🔹 Base64 Encoding")
                
                encoded = base64.b64encode(combined).decode()
                st.code(encoded)
                
                st.markdown("### 💾 Final Stored Value")
                st.write("Stored = Base64(IV + Ciphertext)")
                st.success("✔ Encryption complete")

# === Store Data ===
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    elif not st.session_state.otp_verified:
        st.warning("🔢 Please verify OTP first.")
    else:
        st.subheader("Store Encrypted Data 📦")

        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
                log = {
                    "user": st.session_state.authenticated_user,
                    "action": "data_encrypted",
                    "time": time.time()
                }
                st.session_state.logs.append(log)
            else:
                st.error("All fields required.")

# === Retrieve Data ===
elif choice == "📂 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    elif not st.session_state.otp_verified:
        st.warning("🔢 Please verify OTP first.")
    else:
        st.subheader("Retrieve Data 🔍")

        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No Data Found.")
        else:
            st.write("🔐 Encrypted Data Entries:")

            for item in user_data:
                st.code(item)

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)

                if result:
                    st.success(f"✅ Decrypted: {result}")
                    log = {
                        "user": st.session_state.authenticated_user,
                        "action": "data_decrypted",
                        "time": time.time()
                    }

                    st.session_state.logs.append(log)
                else:
                    st.error("❌ Incorrect Passkey or Corrupted Data.")
elif choice == "📊 Logs":
    st.subheader("System Logs 📊")

    if "logs" in st.session_state:
        for log in st.session_state.logs:
            st.write(log)
    else:
        st.info("No logs available")