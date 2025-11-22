from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from datetime import datetime, timedelta
import mimetypes
import sqlite3
from contextlib import contextmanager
import logging
import smtplib
# Use the correct class names from the ``email.mime`` package.  In
# Python's ``email.mime`` API, the classes are capitalized as
# ``MIMEText`` and ``MIMEMultipart``.  Importing them with the wrong
# capitalization (e.g. ``MimeText`` or ``MimeMultipart``) will raise
# ImportError in Python 3.13+.
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import random
import string
import re

app = Flask(__name__)
# Use a stable secret key so that session cookies remain valid across restarts.
# If you deploy this application, replace the value below with a strong random
# secret key and consider loading it from an environment variable.
app.secret_key = 'a1b2c3d4e5f6g7h8i9j0'
app.config['UPLOAD_FOLDER'] = 'uploads'
# Remove the default maximum file upload size limit. By setting MAX_CONTENT_LENGTH
# to None, uploads are not restricted by Flask (other layers like the web server
# may still impose limits). Previously this was set to 500MB.
app.config['MAX_CONTENT_LENGTH'] = None
app.config['DATABASE'] = 'data/fileserver.db'

# Ρυθμίσεις SMTP
app.config['SMTP_SERVER'] = 'smtp.gmail.com'
app.config['SMTP_PORT'] = 587
app.config['SMTP_USERNAME'] = 'plussd090@gmail.com'  # Αλλαγή με το email σας
app.config['SMTP_PASSWORD'] = 'ncchuzjbkkgidnih'     # Αλλαγή με τον κωδικό εφαρμογής
app.config['BASE_URL'] = 'http://localhost:5000'      # Αλλαγή με το URL της εφαρμογής σας

# Ρύθμιση απλών logs
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

# Απενεργοποίηση Flask logs
import flask.cli
flask.cli.show_server_banner = lambda *args: None
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)

# Database context manager
@contextmanager
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# Initialize database
def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT,
                email_verified BOOLEAN DEFAULT 0,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                parent_id INTEGER,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (parent_id) REFERENCES folders(id)
            );
            
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                size INTEGER NOT NULL,
                mimetype TEXT NOT NULL,
                uploaded TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (folder_id) REFERENCES folders(id)
            );
            
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                token_type TEXT NOT NULL, -- 'email_verify' ή 'password_reset'
                expires TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
            CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
            CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);
            CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
            CREATE INDEX IF NOT EXISTS idx_tokens_user_type ON tokens(user_id, token_type);
        ''')

init_db()

# Συνάρτηση αποστολής email
def send_email(to_email, subject, body):
    try:
        # Create a multipart message using the correct class name.  The
        # ``MIMEMultipart`` class handles the multipart container for
        # email messages.  It must be imported as ``MIMEMultipart`` (see
        # imports above).
        msg = MIMEMultipart()
        msg['From'] = app.config['SMTP_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Attach the HTML body using ``MIMEText``.  ``MIMEText`` should
        # always be imported and referenced with the proper uppercase
        # name, otherwise Python will raise ImportError.
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
        server.starttls()
        server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Σφάλμα αποστολής email: {e}")
        return False

# Συνάρτηση δημιουργίας token
def create_token(user_id, token_type, expires_hours=24, conn=None):
    """
    Create a new token for a user and return it.

    If a database connection is provided via the ``conn`` parameter, the token
    insert will occur on that connection. Otherwise, a new connection will be
    obtained from ``get_db()``. Accepting an optional connection avoids
    nested ``with get_db()`` blocks, which can cause SQLite to lock the
    database when multiple write transactions overlap.
    """
    token = str(uuid.uuid4())
    expires = datetime.now() + timedelta(hours=expires_hours)
    
    if conn is not None:
        conn.execute(
            'INSERT INTO tokens (token, user_id, token_type, expires) VALUES (?, ?, ?, ?)',
            (token, user_id, token_type, expires)
        )
    else:
        with get_db() as conn_local:
            conn_local.execute(
                'INSERT INTO tokens (token, user_id, token_type, expires) VALUES (?, ?, ?, ?)',
                (token, user_id, token_type, expires)
            )
    return token

# Generate and store a short‑lived numeric verification code for email verification.
def create_code(user_id, token_type, expires_minutes=5, length=6, conn=None):
    """
    Create a numeric verification code for a user. The code will expire after
    the specified number of minutes. Returns the code string. If a database
    connection is provided, the code is inserted using that connection to avoid
    nested transactions.
    """
    # Generate a random numeric code of the desired length
    code = ''.join(random.choices(string.digits, k=length))
    expires = datetime.now() + timedelta(minutes=expires_minutes)
    if conn is not None:
        conn.execute(
            'INSERT INTO tokens (token, user_id, token_type, expires) VALUES (?, ?, ?, ?)',
            (code, user_id, token_type, expires)
        )
    else:
        with get_db() as conn_local:
            conn_local.execute(
                'INSERT INTO tokens (token, user_id, token_type, expires) VALUES (?, ?, ?, ?)',
                (code, user_id, token_type, expires)
            )
    return code

# Helper function to construct a relative folder path for a given folder ID.
#
# There are two variants provided: one that returns a sanitized path (using
# ``secure_filename``) and one that returns the raw folder names as stored
# in the database.  The sanitized version is used when constructing file
# system paths for uploads to avoid directory traversal issues.  The raw
# version is used when checking for the existence of directories that may
# have been created using unsanitized names (older versions of the app).

def get_folder_relative_path(conn, folder_id):
    """
    Given a database connection and a folder ID, return the relative path
    (within a user's base upload directory) representing that folder's
    location.  Each segment of the path is sanitized with
    ``secure_filename`` to ensure it is safe for use on the filesystem.

    For example, if there is a folder structure Photos/Vacation and
    ``folder_id`` corresponds to "Vacation", this will return
    ``Photos/Vacation``.  If ``folder_id`` is None or invalid, an empty
    string is returned.
    """
    if not folder_id:
        return ''
    parts = []
    current_id = folder_id
    while current_id:
        folder = conn.execute('SELECT id, name, parent_id FROM folders WHERE id = ?', (current_id,)).fetchone()
        if not folder:
            break
        safe_name = secure_filename(folder['name'])
        parts.insert(0, safe_name)
        current_id = folder['parent_id']
    return os.path.join(*parts) if parts else ''


def get_folder_relative_path_raw(conn, folder_id):
    """
    Similar to ``get_folder_relative_path``, but returns the raw folder
    names as stored in the database (without sanitization).  This is used
    when checking for the existence of directories on disk that may have
    been created using the original, unsanitized names.  If the folder
    hierarchy does not exist in the database, an empty string is returned.
    """
    if not folder_id:
        return ''
    parts = []
    current_id = folder_id
    while current_id:
        folder = conn.execute('SELECT id, name, parent_id FROM folders WHERE id = ?', (current_id,)).fetchone()
        if not folder:
            break
        # Prepend the raw folder name to the list
        parts.insert(0, folder['name'])
        current_id = folder['parent_id']
    return os.path.join(*parts) if parts else ''

# Helper function to determine the base upload directory for a user.  This
# returns a path of the form ``uploads/<sanitized_name>_<id>`` where
# ``sanitized_name`` is the user's name processed through
# ``secure_filename``.  Using the user name (plus the user ID to ensure
# uniqueness) instead of a generic ``user_<id>`` directory provides a
# more human‑friendly directory structure.  If the user's name cannot be
# retrieved or sanitizes to an empty string, a fallback of
# ``user_<id>`` is used.
def get_user_base_path(conn, user_id):
    # Retrieve the user's name from the database
    user = conn.execute('SELECT name FROM users WHERE id = ?', (user_id,)).fetchone()
    sanitized_name = None
    if user and user['name']:
        # Use secure_filename to avoid unsafe characters in directory names
        sanitized_name = secure_filename(user['name'])
    base_upload = app.config['UPLOAD_FOLDER']
    # If we have a sanitized name, construct a directory name using it and
    # the user ID.  Check if a directory with this name already exists.  If
    # not, we will fall back to the legacy "user_<id>" naming scheme to
    # maintain compatibility with existing user folders.
    if sanitized_name:
        candidate_name = f"{sanitized_name}_{user_id}"
        candidate_path = os.path.join(base_upload, candidate_name)
        if os.path.isdir(candidate_path):
            return candidate_path
    # Fallback: legacy directory name
    legacy_name = f"user_{user_id}"
    return os.path.join(base_upload, legacy_name)

# Συνάρτηση επαλήθευσης token
def verify_token(token, token_type):
    with get_db() as conn:
        token_data = conn.execute(
            'SELECT * FROM tokens WHERE token = ? AND token_type = ? AND used = 0 AND expires > ?',
            (token, token_type, datetime.now())
        ).fetchone()
        
        if token_data:
            # Σημειώνουμε το token ως χρησιμοποιημένο
            conn.execute('UPDATE tokens SET used = 1 WHERE id = ?', (token_data['id'],))
            return token_data
        return None

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return redirect(url_for('dashboard'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    # If the user is already logged in (has an active session), redirect them to the dashboard instead of showing the sign‑in page again.
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_ip = request.remote_addr
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            if user and check_password_hash(user['password'], password):
                # If the user's email is not yet verified, send a one‑time code instead of a link
                if not user['email_verified']:
                    # Generate a short‑lived numeric code (5 minute expiry)
                    code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
                    # Prepare email with the verification code
                    email_body = f"""
                    <html>
                    <body>
                        <h2>Email Verification Code</h2>
                        <p>Your verification code is: <strong>{code}</strong></p>
                        <p>This code is valid for 5 minutes. Please enter it to verify your account.</p>
                    </body>
                    </html>
                    """
                    send_email(email, "Email Verification Code - File Upload Server", email_body)
                    flash('A verification code has been sent to your email. Please enter it to verify your account.', 'success')
                    # Store user info in session so that /verify_code can associate the code with the user
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    return redirect(url_for('verify_code'))

                # Email already verified: log the user in normally
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                logger.info(f"Σύνδεση επιτυχής - {email} από IP: {user_ip}")
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                logger.info(f"Αποτυχημένη σύνδεση - {email} από IP: {user_ip}")
                flash('Invalid email or password', 'error')
    
    # Determine whether we should show the login form (instead of the registration form).
    # Accept multiple possible query parameters for flexibility (e.g., show_login, show_login, login).
    show_login = False
    for key in ['show_login', 'show_login', 'login']:
        val = request.args.get(key)
        if val and val.lower() in ['1', 'true', 'yes']:
            show_login = True
            break
    return render_template('signin.html', show_login=show_login)

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name', '').strip()
    
    with get_db() as conn:
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing:
            flash('Email already registered', 'error')
            return redirect(url_for('signin'))

        # Require a non-empty name
        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('signin'))
        
        conn.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                    (email, generate_password_hash(password), name))
        
        user = conn.execute('SELECT id, name FROM users WHERE email = ?', (email,)).fetchone()
        # Create a directory for the new user under the uploads folder.  Use
        # the sanitized user name combined with the user ID to ensure a
        # human‑friendly yet unique directory, e.g. "john_doe_42".  Fallback
        # to "user_<id>" if the name cannot be sanitized.
        sanitized_name = secure_filename(user['name']) if user['name'] else ''
        if sanitized_name:
            user_folder_name = f"{sanitized_name}_{user['id']}"
        else:
            user_folder_name = f"user_{user['id']}"
        user_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], user_folder_name)
        os.makedirs(user_folder_path, exist_ok=True)
        
        # Generate a numeric verification code valid for 5 minutes
        code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
        
        # Send email with verification code instead of a link
        email_body = f"""
        <html>
        <body>
            <h2>Welcome to File Upload Server!</h2>
            <p>Your verification code is: <strong>{code}</strong></p>
            <p>This code is valid for 5 minutes. Please enter it to activate your account.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
        </body>
        </html>
        """
        
        if send_email(email, "Verify Your Email - File Upload Server", email_body):
            flash('Account created successfully! A verification code has been sent to your email. Please enter it to verify your account.', 'success')
        else:
            flash('Account created successfully! But we could not send the verification code email. Please contact support.', 'warning')
        
        # Store session details so the user can verify their code
        session['user_id'] = user['id']
        session['user_email'] = email

    logger.info(f"Νέος χρήστης - {email}")
    return redirect(url_for('verify_code'))

# Route για αναμονή επαλήθευσης
@app.route('/verify_pending')
def verify_pending():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return render_template('verify-pending.html')

# Route για επαλήθευση email
@app.route('/verify_email/<token>')
def verify_email(token):
    token_data = verify_token(token, 'email_verify')
    
    if token_data:
        with get_db() as conn:
            conn.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (token_data['user_id'],))
        
        flash('Email verified successfully! You can now use all features.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('signin'))

# Route for verifying a numeric code sent via email.  When a user registers
# or attempts to sign in without a verified email, a short‑lived code is
# generated and emailed to them.  This route presents a form where the
# user can enter the code and their account password.  If both the code
# and password match, the user's email is marked as verified.
@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    # User must be logged in (via session) to verify their code
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        # Only verify the code; no password is required.  This allows
        # users to confirm their email using just the numeric code sent
        # via email.
        with get_db() as conn:
            # Find a valid (unused, unexpired) email_code token for this user
            token_data = conn.execute(
                'SELECT * FROM tokens WHERE token = ? AND token_type = ? AND used = 0 AND expires > ? AND user_id = ?',
                (code, 'email_code', datetime.now(), session['user_id'])
            ).fetchone()
            if not token_data:
                flash('Invalid or expired verification code.', 'error')
                return render_template('verify-code.html')
            # Mark the token as used and verify the user's email
            conn.execute('UPDATE tokens SET used = 1 WHERE id = ?', (token_data['id'],))
            conn.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (session['user_id'],))
        flash('Email verified successfully! You can now use all features.', 'success')
        return redirect(url_for('dashboard'))
    # GET request: show the code verification form
    return render_template('verify-code.html')

# Route για επαναποστολή verification email
@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if user and not user['email_verified']:
            # Create a new 5‑minute verification code and send it to the user
            code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
            email_body = f"""
            <html>
            <body>
                <h2>Email Verification Code</h2>
                <p>Your new verification code is: <strong>{code}</strong></p>
                <p>This code is valid for 5 minutes. Please enter it to verify your account.</p>
            </body>
            </html>
            """
            
            if send_email(user['email'], "Email Verification Code - File Upload Server", email_body):
                flash('A new verification code has been sent!', 'success')
            else:
                flash('Error sending verification code. Please try again later.', 'error')
        else:
            flash('Email is already verified or user not found.', 'info')
    
    # Always redirect to the code verification page so user can enter the new code
    return redirect(url_for('verify_code'))

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                # Δημιουργία token ανάκτησης κωδικού
                # Use the existing DB connection to avoid nested writes
                token = create_token(user['id'], 'password_reset', expires_hours=1, conn=conn)  # 1 ώρα ισχύς
                
                # Αποστολή email ανάκτησης
                reset_url = f"{app.config['BASE_URL']}/reset_password/{token}"
                email_body = f"""
                <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>You requested a password reset. Click the link below to reset your password:</p>
                    <a href="{reset_url}" style="background-color: #66c7ea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;">Reset Password</a>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </body>
                </html>
                """
                
                if send_email(email, "Password Reset - File Upload Server", email_body):
                    flash('If an account with that email exists, a password reset link has been sent.', 'success')
                else:
                    flash('Error sending reset email. Please try again later.', 'error')
            else:
                # Για ασφάλεια, δεν αποκαλύπτουμε αν το email υπάρχει
                flash('If an account with that email exists, a password reset link has been sent.', 'success')
        
        return redirect(url_for('signin'))
    
    return render_template('request-password-reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Επαλήθευση του token
    token_data = verify_token(token, 'password_reset')
    
    if not token_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('request_password_reset'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset-password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('reset-password.html', token=token)
        
        # Ενημέρωση του κωδικού
        with get_db() as conn:
            conn.execute(
                'UPDATE users SET password = ? WHERE id = ?',
                (generate_password_hash(password), token_data['user_id'])
            )
        
        flash('Password has been reset successfully!', 'success')
        return redirect(url_for('signin'))
    
    return render_template('reset-password.html', token=token)

@app.route('/logout')
def logout():
    email = session.get('user_email', 'Unknown')
    session.clear()
    logger.info(f"Αποσύνδεση - {email}")
    flash('Logged out successfully', 'success')
    # Redirect to the sign‑in page and instruct it to show the login form instead of the registration form.
    return redirect(url_for('signin', show_login=1))

@app.route('/dashboard')
@app.route('/dashboard/<int:folder_id>')
def dashboard(folder_id=None):
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        # Get current folder info
        current_folder = None
        breadcrumbs = []
        
        if folder_id:
            current_folder = conn.execute(
                'SELECT * FROM folders WHERE id = ? AND user_id = ?',
                (folder_id, session['user_id'])
            ).fetchone()
            
            if current_folder:
                # Build breadcrumb trail
                breadcrumbs = get_breadcrumbs(conn, folder_id)
        
        # Get folders in current location.  We need to ensure that
        # folders which have been manually deleted on the filesystem do not
        # appear in the list.  We check both the sanitized and raw
        # directory names when determining existence.  If neither exists,
        # the folder record is removed from the database.
        folder_rows = conn.execute(
            'SELECT * FROM folders WHERE user_id = ? AND parent_id IS ? ORDER BY name',
            (session['user_id'], folder_id)
        ).fetchall()
        folders = []
        for row in folder_rows:
            folder_dict = dict(row)
            # Determine the base path for the current user.  Use the sanitized
            # user name combined with the ID for a more readable folder name.
            user_base = get_user_base_path(conn, session['user_id'])
            # Build both sanitized and raw relative paths
            rel_folder_path_safe = get_folder_relative_path(conn, folder_dict['id'])
            rel_folder_path_raw = get_folder_relative_path_raw(conn, folder_dict['id'])
            # Determine the physical path of this folder.  Prefer the raw
            # path if it exists; otherwise fall back to the sanitized path.
            physical_folder_path = None
            # Check raw path if available
            if rel_folder_path_raw:
                raw_path = os.path.join(user_base, rel_folder_path_raw)
                if os.path.isdir(raw_path):
                    physical_folder_path = raw_path
            # If raw path doesn't exist, check sanitized path
            if physical_folder_path is None:
                if rel_folder_path_safe:
                    safe_path = os.path.join(user_base, rel_folder_path_safe)
                else:
                    safe_path = user_base
                if os.path.isdir(safe_path):
                    physical_folder_path = safe_path
            # If neither the raw nor sanitized directory exists, remove the folder record and skip it
            if physical_folder_path is None:
                conn.execute('DELETE FROM folders WHERE id = ?', (folder_dict['id'],))
                continue
            # Sum the sizes of all files directly in this folder for this user.  Subfolder sizes are not included.
            size_row = conn.execute(
                'SELECT SUM(size) as total FROM files WHERE user_id = ? AND folder_id = ?',
                (session['user_id'], folder_dict['id'])
            ).fetchone()
            folder_dict['size'] = size_row['total'] or 0
            folders.append(folder_dict)
        
        # Get files in current location.  We will filter out any file
        # entries whose underlying file is missing from disk.  To handle
        # inconsistencies between sanitized and raw folder names, attempt
        # to build both raw and sanitized paths and check which exists.
        file_rows = conn.execute(
            'SELECT * FROM files WHERE user_id = ? AND folder_id IS ? ORDER BY uploaded DESC',
            (session['user_id'], folder_id)
        ).fetchall()
        files = []
        for row in file_rows:
            file_dict = dict(row)
            # Determine the base path for the user of this file.  Use sanitized user name.
            user_base = get_user_base_path(conn, file_dict['user_id'])
            # Determine relative folder paths (safe and raw) for the file's folder
            rel_path_safe = ''
            rel_path_raw = ''
            if file_dict['folder_id']:
                rel_path_safe = get_folder_relative_path(conn, file_dict['folder_id'])
                rel_path_raw = get_folder_relative_path_raw(conn, file_dict['folder_id'])
            # Build potential physical paths using raw and safe folder names
            potential_paths = []
            # Raw path
            if rel_path_raw:
                potential_paths.append(os.path.join(user_base, rel_path_raw, file_dict['stored_name']))
            # Safe path
            if rel_path_safe:
                potential_paths.append(os.path.join(user_base, rel_path_safe, file_dict['stored_name']))
            # Root-level (no folder)
            if not file_dict['folder_id']:
                potential_paths.append(os.path.join(user_base, file_dict['stored_name']))
            # Determine which path actually exists
            physical_path = None
            for p in potential_paths:
                if os.path.isfile(p):
                    physical_path = p
                    break
            # If no candidate path exists, remove the DB entry and skip it
            if physical_path is None:
                conn.execute('DELETE FROM files WHERE id = ?', (file_dict['id'],))
                continue
            files.append(file_dict)
    
    return render_template('dashboard.html', 
                         files=files, 
                         folders=folders,
                         current_folder=current_folder,
                         breadcrumbs=breadcrumbs)

def get_breadcrumbs(conn, folder_id):
    breadcrumbs = []
    current_id = folder_id
    
    while current_id:
        folder = conn.execute('SELECT * FROM folders WHERE id = ?', (current_id,)).fetchone()
        if folder:
            breadcrumbs.insert(0, dict(folder))
            current_id = folder['parent_id']
        else:
            break
    
    return breadcrumbs

@app.route('/create_folder', methods=['POST'])
def create_folder():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    folder_name = request.form.get('folder_name', '').strip()
    parent_id = request.form.get('parent_id')
    
    if not folder_name:
        return jsonify({'error': 'Folder name is required'}), 400
    
    if parent_id:
        parent_id = int(parent_id)
    else:
        parent_id = None
    
    with get_db() as conn:
        # Insert the new folder record
        conn.execute(
            'INSERT INTO folders (name, user_id, parent_id) VALUES (?, ?, ?)',
            (folder_name, session['user_id'], parent_id)
        )
        # Compute the physical path where this folder should live.  Determine
        # the user base directory using the sanitized user name.
        user_base = get_user_base_path(conn, session['user_id'])
        # Build the relative path for the parent folder (if any)
        rel_parent_path = ''
        if parent_id:
            rel_parent_path = get_folder_relative_path(conn, parent_id)
        # Create the new directory inside the user's base path
        # If rel_parent_path is not empty, join it
        if rel_parent_path:
            folder_path = os.path.join(user_base, rel_parent_path, folder_name)
        else:
            folder_path = os.path.join(user_base, folder_name)
        os.makedirs(folder_path, exist_ok=True)
    logger.info(f"Νέος φάκελος - {folder_name}")
    return jsonify({'success': True})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        logger.info("Upload αποτυχία - Μη συνδεδεμένος")
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    folder_id = request.form.get('folder_id')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{filename}"
        # We will perform all database operations inside a single context to
        # avoid nested connections.  This allows us to compute the user's
        # base directory, resolve the target folder path, and insert the
        # file metadata in one transaction.
        with get_db() as conn:
            # Determine the base directory for this user using the sanitized
            # user name
            user_base = get_user_base_path(conn, session['user_id'])
            # Build the relative path for the target folder (if any)
            rel_path = ''
            if folder_id:
                folder_id_int = int(folder_id)
                rel_path = get_folder_relative_path(conn, folder_id_int)
                folder_id = folder_id_int
            else:
                folder_id = None
            # Build the final directory path (user base + optional folder path)
            if rel_path:
                upload_dir = os.path.join(user_base, rel_path)
            else:
                upload_dir = user_base
            # Ensure directory exists
            os.makedirs(upload_dir, exist_ok=True)
            # Save the file to the computed directory
            filepath = os.path.join(upload_dir, unique_filename)
            file.save(filepath)
            file_size = os.path.getsize(filepath)
            # Insert file metadata into the database
            conn.execute(
                'INSERT INTO files (original_name, stored_name, user_id, folder_id, size, mimetype) VALUES (?, ?, ?, ?, ?, ?)',
                (filename, unique_filename, session['user_id'], folder_id, file_size, 
                 mimetypes.guess_type(filename)[0] or 'application/octet-stream')
            )
        logger.info(f"Upload επιτυχές - {filename}")
        return jsonify({'success': True})

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        ).fetchone()
    
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Build possible absolute paths to the requested file using both raw and
    # sanitized folder names.  We select the first path that exists.  Use
    # the sanitized user name for the base directory.
    with get_db() as _conn:
        user_base = get_user_base_path(_conn, file_info['user_id'])
    rel_path_safe = ''
    rel_path_raw = ''
    if file_info['folder_id']:
        with get_db() as conn:
            rel_path_safe = get_folder_relative_path(conn, file_info['folder_id'])
            rel_path_raw = get_folder_relative_path_raw(conn, file_info['folder_id'])
    candidate_paths = []
    if rel_path_raw:
        candidate_paths.append(os.path.join(user_base, rel_path_raw, file_info['stored_name']))
    if rel_path_safe:
        candidate_paths.append(os.path.join(user_base, rel_path_safe, file_info['stored_name']))
    # Root-level path
    candidate_paths.append(os.path.join(user_base, file_info['stored_name']))
    filepath = None
    for p in candidate_paths:
        if os.path.isfile(p):
            filepath = p
            break
    if filepath is None:
        flash('File not found on server', 'error')
        return redirect(url_for('dashboard'))
    logger.info(f"Download - {file_info['original_name']}")
    return send_file(filepath, as_attachment=True, download_name=file_info['original_name'])

@app.route('/file/<int:file_id>')
def serve_file(file_id):
    """
    Serve a stored file inline with the correct MIME type. This route
    allows media like videos, audio, and images to be embedded directly
    in pages without forcing a download. Only authenticated users can
    access their own files.
    """
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        ).fetchone()
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    # Build potential absolute paths for the requested file using both raw
    # and sanitized folder names.  Resolve to the first existing path.
    # Determine the base directory for this user using the sanitized user name
    with get_db() as _conn:
        user_base = get_user_base_path(_conn, file_info['user_id'])
    rel_path_safe = ''
    rel_path_raw = ''
    if file_info['folder_id']:
        with get_db() as conn:
            rel_path_safe = get_folder_relative_path(conn, file_info['folder_id'])
            rel_path_raw = get_folder_relative_path_raw(conn, file_info['folder_id'])
    candidate_paths = []
    if rel_path_raw:
        candidate_paths.append(os.path.abspath(os.path.join(user_base, rel_path_raw, file_info['stored_name'])))
    if rel_path_safe:
        candidate_paths.append(os.path.abspath(os.path.join(user_base, rel_path_safe, file_info['stored_name'])))
    # Root-level path
    candidate_paths.append(os.path.abspath(os.path.join(user_base, file_info['stored_name'])))
    abs_path = None
    for p in candidate_paths:
        if os.path.isfile(p):
            abs_path = p
            break
    if abs_path is None:
        flash('File not found on server', 'error')
        return redirect(url_for('dashboard'))
    # Serve the file inline without forcing a download.  Avoid specifying
    # download_name to maintain compatibility with older Flask versions.
    return send_file(
        abs_path,
        as_attachment=False,
        mimetype=file_info['mimetype']
    )

@app.route('/view/<int:file_id>')
def view_file(file_id):
    """
    Render a simple viewing page for media files such as videos, images,
    and audio. For unsupported file types, provide a download link instead.
    """
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        ).fetchone()
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    # Determine file category for rendering
    mimetype = file_info['mimetype'] or ''
    ext = ''
    if '.' in file_info['original_name']:
        ext = file_info['original_name'].rsplit('.', 1)[-1].lower()
    is_video = mimetype.startswith('video/') or ext in ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'm4v']
    is_audio = mimetype.startswith('audio/') or ext in ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a']
    is_image = mimetype.startswith('image/') or ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']
    return render_template(
        'file_view.html',
        file=file_info,
        is_video=is_video,
        is_audio=is_audio,
        is_image=is_image
    )

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Παίρνουμε την IP του χρήστη
    user_ip = request.remote_addr
    
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        ).fetchone()
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete physical file: build possible paths within the user's directory.  We
        # support both raw and sanitized folder names to handle legacy
        # directories.
        # Determine the base directory for this user using the sanitized user name
        user_base = get_user_base_path(conn, file_info['user_id'])
        rel_path_safe = ''
        rel_path_raw = ''
        if file_info['folder_id']:
            rel_path_safe = get_folder_relative_path(conn, file_info['folder_id'])
            rel_path_raw = get_folder_relative_path_raw(conn, file_info['folder_id'])
        # Build candidate file paths (raw first, then safe, then root)
        candidate_paths = []
        if rel_path_raw:
            candidate_paths.append(os.path.join(user_base, rel_path_raw, file_info['stored_name']))
        if rel_path_safe:
            candidate_paths.append(os.path.join(user_base, rel_path_safe, file_info['stored_name']))
        if not file_info['folder_id']:
            candidate_paths.append(os.path.join(user_base, file_info['stored_name']))
        # Remove the first existing candidate
        for fp in candidate_paths:
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except Exception:
                    pass
                break
        
        # Remove from database
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
    
    # ΝΕΟ: Μήνυμα καταγραφής για τη διαγραφή
    logger.info(f"Διαγραφή αρχείου - '{file_info['original_name']}' από χρήστη {session['user_email']} (IP: {user_ip})")
    return jsonify({'success': True})

@app.route('/delete_folder/<int:folder_id>', methods=['POST'])
def delete_folder(folder_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    with get_db() as conn:
        folder = conn.execute(
            'SELECT * FROM folders WHERE id = ? AND user_id = ?',
            (folder_id, session['user_id'])
        ).fetchone()
        
        if not folder:
            return jsonify({'error': 'Folder not found'}), 404
        
        # Check if folder has files
        files = conn.execute('SELECT COUNT(*) as count FROM files WHERE folder_id = ?', (folder_id,)).fetchone()
        if files['count'] > 0:
            return jsonify({'error': 'Folder must be empty'}), 400
        
        # Check if folder has subfolders
        subfolders = conn.execute('SELECT COUNT(*) as count FROM folders WHERE parent_id = ?', (folder_id,)).fetchone()
        if subfolders['count'] > 0:
            return jsonify({'error': 'Folder must be empty'}), 400
        
        # Remove the folder record from the database
        conn.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
        # Remove the physical directory on disk.  We attempt to remove both
        # raw and sanitized directory names.  Use os.rmdir first; if it fails
        # because of hidden files (directory not empty), fall back to
        # shutil.rmtree to force deletion.  Ignore errors if the directory
        # does not exist.
        user_base = get_user_base_path(conn, session['user_id'])
        rel_path_safe = get_folder_relative_path(conn, folder_id)
        rel_path_raw = get_folder_relative_path_raw(conn, folder_id)
        candidate_dirs = []
        if rel_path_raw:
            candidate_dirs.append(os.path.join(user_base, rel_path_raw))
        if rel_path_safe:
            candidate_dirs.append(os.path.join(user_base, rel_path_safe))
        for d in candidate_dirs:
            try:
                os.rmdir(d)
            except FileNotFoundError:
                # Directory doesn't exist; nothing to remove
                continue
            except OSError:
                # Directory may contain hidden files; try recursive removal
                try:
                    import shutil
                    shutil.rmtree(d)
                except Exception:
                    pass
    logger.info(f"Διαγραφή φακέλου - {folder['name']}")
    return jsonify({'success': True})

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        user_info = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        
        file_count = conn.execute(
            'SELECT COUNT(*) as count FROM files WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()['count']
        
        total_size = conn.execute(
            'SELECT SUM(size) as total FROM files WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()['total'] or 0
        
        folder_count = conn.execute(
            'SELECT COUNT(*) as count FROM folders WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()['count']
    
    return render_template('account.html', 
                         user=user_info, 
                         email=session['user_email'],
                         file_count=file_count,
                         total_size=total_size,
                         folder_count=folder_count)

# Middleware για έλεγχο επαλήθευσης email
@app.before_request
def check_email_verified():
    # Permit access to certain routes even if the user has not yet verified their email.  In
    # addition to static assets and the old verify_email route, allow the code
    # verification route so the user can enter their code and password.  Also
    # permit sign‑in, resending codes and logging out.
    if 'user_id' in session and request.endpoint not in ['static', 'verify_email', 'verify_pending', 'logout', 'signin', 'resend_verification', 'verify_code']:
        with get_db() as conn:
            user = conn.execute('SELECT email_verified FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if user and not user['email_verified'] and request.endpoint != 'verify_pending':
                return redirect(url_for('verify_pending'))

if __name__ == '__main__':
    print("=" * 40)
    print("File Server - Εκκίνηση...")
    print("=" * 40)
    print(f"Διεύθυνση: http://localhost:5000")
    print(f"Φάκελος uploads: {app.config['UPLOAD_FOLDER']}")
    print(f"Βάση δεδομένων: {app.config['DATABASE']}")
    print("=" * 40)
    print("ΣΗΜΑΝΤΙΚΟ: Ρυθμίστε τα SMTP credentials στο server.py")
    print("για να λειτουργήσει το σύστημα επαλήθευσης email")
    print("=" * 40)
    
    # Απενεργοποίηση debug messages
    import warnings
    warnings.filterwarnings("ignore")
    
    app.run(debug=False, host='0.0.0.0', port=5000)