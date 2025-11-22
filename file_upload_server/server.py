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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import uuid
import random
import string
import re

app = Flask(__name__)
app.secret_key = 'a1b2c3d4e5f6g7h8i9j0'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = None
app.config['CHUNK_TEMP_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_chunks')
app.config['DATABASE'] = 'data/fileserver.db'

ADMIN_ID = 1
ADMIN_EMAIL = os.environ.get('FILESERVER_ADMIN_EMAIL')

app.config['SMTP_SERVER'] = 'smtp.gmail.com'
app.config['SMTP_PORT'] = 587
app.config['SMTP_USERNAME'] = 'plussd090@gmail.com'
app.config['SMTP_PASSWORD'] = 'ncchuzjbkkgidnih'
app.config['BASE_URL'] = 'https://thomast.uk'

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger()

import flask.cli
flask.cli.show_server_banner = lambda *args: None
logging.getLogger('werkzeug').setLevel(logging.WARNING)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs(app.config['CHUNK_TEMP_FOLDER'], exist_ok=True)

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
                is_public BOOLEAN DEFAULT 0,
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
                is_public BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (folder_id) REFERENCES folders(id)
            );
            
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                token_type TEXT NOT NULL,
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
        try:
            cols = [row[1] for row in conn.execute('PRAGMA table_info(files)').fetchall()]
            if 'is_public' not in cols:
                conn.execute('ALTER TABLE files ADD COLUMN is_public BOOLEAN DEFAULT 0')
        except Exception:
            pass
        try:
            cols = [row[1] for row in conn.execute('PRAGMA table_info(folders)').fetchall()]
            if 'is_public' not in cols:
                conn.execute('ALTER TABLE folders ADD COLUMN is_public BOOLEAN DEFAULT 0')
        except Exception:
            pass

init_db()

def ensure_user_folder(user_id, conn):
    user = conn.execute('SELECT id, name FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return None
    # ΚΡΑΤΑΜΕ secure_filename() ΓΙΑ USERNAMES
    sanitized_name = secure_filename(user['name']) if user['name'] else ''
    if sanitized_name:
        user_folder_name = f"{sanitized_name}_{user['id']}"
    else:
        user_folder_name = f"user_{user['id']}"
    user_folder_path = os.path.join(app.config['UPLOAD_FOLDER'], user_folder_name)
    os.makedirs(user_folder_path, exist_ok=True)
    return user_folder_path

def render_email_template(template_name, **context):
    template_content = render_template(f'emails/{template_name}', **context)
    return render_template('emails/base_email.html', content=template_content)

def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"FileCloud Pro <{app.config['SMTP_USERNAME']}>"
        msg['To'] = to_email
        msg['Subject'] = subject

        try:
            plain_body = re.sub('<[^<]+?>', '', body)
            plain_body = re.sub('\s+\n', '\n', plain_body).strip()
        except Exception:
            plain_body = body
        plain_body = f"FileCloud Pro\n\n{plain_body}"

        msg.attach(MIMEText(plain_body, 'plain'))
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

def create_token(user_id, token_type, expires_hours=24, conn=None):
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

def create_code(user_id, token_type, expires_minutes=5, length=6, conn=None):
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

def get_folder_relative_path(conn, folder_id):
    if not folder_id:
        return ''
    parts = []
    current_id = folder_id
    
    while current_id:
        folder = conn.execute('SELECT id, name, parent_id FROM folders WHERE id = ?', (current_id,)).fetchone()
        if not folder:
            break
        # ΑΦΑΙΡΕΣΗ secure_filename() ΜΟΝΟ ΓΙΑ ΦΑΚΕΛΟΥΣ
        safe_name = folder['name']
        parts.insert(0, safe_name)
        current_id = folder['parent_id']
    
    return os.path.join(*parts) if parts else ''

def get_folder_relative_path_raw(conn, folder_id):
    if not folder_id:
        return ''
    parts = []
    current_id = folder_id
    
    while current_id:
        folder = conn.execute('SELECT id, name, parent_id FROM folders WHERE id = ?', (current_id,)).fetchone()
        if not folder:
            break
        parts.insert(0, folder['name'])
        current_id = folder['parent_id']
    
    return os.path.join(*parts) if parts else ''

def get_user_base_path(conn, user_id):
    user = conn.execute('SELECT name FROM users WHERE id = ?', (user_id,)).fetchone()
    sanitized_name = None
    if user and user['name']:
        sanitized_name = secure_filename(user['name'])  # ΚΡΑΤΑΜΕ ΓΙΑ USERNAMES
    base_upload = app.config['UPLOAD_FOLDER']
    if sanitized_name:
        candidate_name = f"{sanitized_name}_{user_id}"
        candidate_path = os.path.join(base_upload, candidate_name)
        if os.path.isdir(candidate_path):
            return candidate_path
    legacy_name = f"user_{user_id}"
    return os.path.join(base_upload, legacy_name)

def verify_token(token, token_type):
    with get_db() as conn:
        token_data = conn.execute(
            'SELECT * FROM tokens WHERE token = ? AND token_type = ? AND used = 0 AND expires > ?',
            (token, token_type, datetime.now())
        ).fetchone()
        
        if token_data:
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
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_ip = request.remote_addr
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            if user and check_password_hash(user['password'], password):
                if not user['email_verified']:
                    code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
                    email_body = render_email_template(
                        'verification_code.html',
                        verification_code=code
                    )
                    send_email(email, "Email Verification Code - FileCloud Pro", email_body)
                    flash('A verification code has been sent to your email. Please enter it to verify your account.', 'success')
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    return redirect(url_for('verify_code'))

                session['user_id'] = user['id']
                session['user_email'] = user['email']
                logger.info(f"Σύνδεση επιτυχής - {email} από IP: {user_ip}")
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                logger.info(f"Αποτυχημένη σύνδεση - {email} από IP: {user_ip}")
                flash('Invalid email or password', 'error')
    
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

        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('signin'))
        
        conn.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                    (email, generate_password_hash(password), name))
        
        user = conn.execute('SELECT id, name FROM users WHERE email = ?', (email,)).fetchone()
        
        code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
        
        email_body = render_email_template(
            'welcome_email.html',
            user_name=name,
            verification_code=code
        )
        
        if send_email(email, "Welcome to FileCloud Pro - Verify Your Email", email_body):
            flash('Account created successfully! A verification code has been sent to your email. Please enter it to verify your account.', 'success')
        else:
            flash('Account created successfully! But we could not send the verification code email. Please contact support.', 'warning')
        
        session['user_id'] = user['id']
        session['user_email'] = email

    logger.info(f"Νέος χρήστης - {email}")
    return redirect(url_for('verify_code'))

@app.route('/verify_pending')
def verify_pending():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return render_template('verify-pending.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    token_data = verify_token(token, 'email_verify')
    
    if token_data:
        with get_db() as conn:
            conn.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (token_data['user_id'],))
            ensure_user_folder(token_data['user_id'], conn)
        
        flash('Email verified successfully! You can now use all features.', 'success')
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('signin'))

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        with get_db() as conn:
            token_data = conn.execute(
                'SELECT * FROM tokens WHERE token = ? AND token_type = ? AND used = 0 AND expires > ? AND user_id = ?',
                (code, 'email_code', datetime.now(), session['user_id'])
            ).fetchone()
            if not token_data:
                flash('Invalid or expired verification code.', 'error')
                return render_template('verify-code.html')
            conn.execute('UPDATE tokens SET used = 1 WHERE id = ?', (token_data['id'],))
            conn.execute('UPDATE users SET email_verified = 1 WHERE id = ?', (session['user_id'],))
            ensure_user_folder(session['user_id'], conn)
        flash('Email verified successfully! You can now use all features.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('verify-code.html')

@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if user and not user['email_verified']:
            code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
            email_body = render_email_template(
                'verification_code.html',
                verification_code=code
            )
            
            if send_email(user['email'], "Email Verification Code - FileCloud Pro", email_body):
                flash('A new verification code has been sent!', 'success')
            else:
                flash('Error sending verification code. Please try again later.', 'error')
        else:
            flash('Email is already verified or user not found.', 'info')
    
    return redirect(url_for('verify_code'))

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            email = email.strip().lower()
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user:
                if not user['email_verified']:
                    code = create_code(user['id'], 'email_code', expires_minutes=5, conn=conn)
                    email_body = render_email_template(
                        'verification_code.html',
                        verification_code=code
                    )
                    send_email(email, "Email Verification Code - FileCloud Pro", email_body)
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    flash('You must verify your email before resetting your password. A verification code has been sent.', 'error')
                    return redirect(url_for('verify_code'))
                else:
                    token = create_token(user['id'], 'password_reset', expires_hours=1, conn=conn)
                    reset_url = f"{app.config['BASE_URL']}/reset_password/{token}"
                    email_body = render_email_template(
                        'password_reset.html',
                        reset_url=reset_url
                    )
                    if send_email(email, "Password Reset - FileCloud Pro", email_body):
                        flash('If an account with that email exists and is verified, a password reset link has been sent.', 'success')
                    else:
                        flash('Error sending reset email. Please try again later.', 'error')
            else:
                flash('If an account with that email exists and is verified, a password reset link has been sent.', 'success')
        return redirect(url_for('signin'))
    return render_template('request-password-reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
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
    return redirect(url_for('signin', show_login=1))

@app.route('/dashboard')
@app.route('/dashboard/<int:folder_id>')
def dashboard(folder_id=None):
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        current_folder = None
        breadcrumbs = []
        
        if folder_id:
            # ΕΠΕΝΔΥΣΗ: Επιτρέψτε πρόσβαση σε δημόσιους φακέλους όλων των χρηστών
            current_folder = conn.execute(
                'SELECT * FROM folders WHERE id = ? AND (user_id = ? OR is_public = 1)',
                (folder_id, session['user_id'])
            ).fetchone()
            
            if current_folder:
                breadcrumbs = get_breadcrumbs(conn, folder_id)
        
        # ΕΠΕΝΔΥΣΗ: Εμφάνιση όλων των δημόσιων φακέλων + προσωπικών φακέλων
        folder_rows = conn.execute(
            '''SELECT * FROM folders 
               WHERE (user_id = ? OR is_public = 1) 
               AND parent_id IS ? 
               ORDER BY name''',
            (session['user_id'], folder_id)
        ).fetchall()
        
        # DEBUG: Log public folders
        public_folders = conn.execute(
            'SELECT id, name, user_id, is_public FROM folders WHERE is_public = 1'
        ).fetchall()
        
        logger.info(f"DEBUG: Found {len(public_folders)} public folders:")
        for folder in public_folders:
            logger.info(f"DEBUG: Public Folder - ID: {folder['id']}, Name: {folder['name']}, Owner: {folder['user_id']}")
        
        folders = []
        for row in folder_rows:
            folder_dict = dict(row)
            # Χρησιμοποιήστε το user_id του ιδιοκτήτη του φακέλου
            folder_owner_id = folder_dict['user_id']
            user_base = get_user_base_path(conn, folder_owner_id)
            
            rel_folder_path_safe = get_folder_relative_path(conn, folder_dict['id'])
            rel_folder_path_raw = get_folder_relative_path_raw(conn, folder_dict['id'])
            
            physical_folder_path = None
            if rel_folder_path_raw:
                raw_path = os.path.join(user_base, rel_folder_path_raw)
                if os.path.isdir(raw_path):
                    physical_folder_path = raw_path
                    
            if physical_folder_path is None and rel_folder_path_safe:
                safe_path = os.path.join(user_base, rel_folder_path_safe)
                if os.path.isdir(safe_path):
                    physical_folder_path = safe_path
                    
            if physical_folder_path is None:
                # Αν ο φάκελος δεν υπάρχει πια, διαγράψτε τον από τη βάση
                conn.execute('DELETE FROM folders WHERE id = ?', (folder_dict['id'],))
                continue
                
            # Υπολογισμός μεγέθους φακέλου
            size_row = conn.execute(
                'SELECT SUM(size) as total FROM files WHERE folder_id = ?',
                (folder_dict['id'],)
            ).fetchone()
            folder_dict['size'] = size_row['total'] or 0
            folders.append(folder_dict)
        
        # ΕΠΕΝΔΥΣΗ: Εμφάνιση αρχείων από δημόσιους φακέλους άλλων χρηστών
        if folder_id is None:
            file_rows = conn.execute(
                '''SELECT * FROM files 
                   WHERE (user_id = ? OR is_public = 1) 
                   AND folder_id IS NULL 
                   ORDER BY uploaded DESC''',
                (session['user_id'],)
            ).fetchall()
        else:
            file_rows = conn.execute(
                '''SELECT * FROM files 
                   WHERE (user_id = ? OR is_public = 1) 
                   AND folder_id = ? 
                   ORDER BY uploaded DESC''',
                (session['user_id'], folder_id)
            ).fetchall()
            
        files = []
        for row in file_rows:
            file_dict = dict(row)
            # Χρησιμοποιήστε το user_id του ιδιοκτήτη του αρχείου
            file_owner_id = file_dict['user_id']
            user_base = get_user_base_path(conn, file_owner_id)
            
            rel_path_safe = ''
            rel_path_raw = ''
            if file_dict['folder_id']:
                rel_path_safe = get_folder_relative_path(conn, file_dict['folder_id'])
                rel_path_raw = get_folder_relative_path_raw(conn, file_dict['folder_id'])
                
            potential_paths = []
            if rel_path_raw:
                potential_paths.append(os.path.join(user_base, rel_path_raw, file_dict['stored_name']))
            if rel_path_safe:
                potential_paths.append(os.path.join(user_base, rel_path_safe, file_dict['stored_name']))
            if not file_dict['folder_id']:
                potential_paths.append(os.path.join(user_base, file_dict['stored_name']))
                
            physical_path = None
            for p in potential_paths:
                if os.path.isfile(p):
                    physical_path = p
                    break
                    
            if physical_path is None:
                conn.execute('DELETE FROM files WHERE id = ?', (file_dict['id'],))
                continue
                
            files.append(file_dict)
    
    is_admin = False
    if session.get('user_id') == ADMIN_ID:
        is_admin = True
    if ADMIN_EMAIL and session.get('user_email') == ADMIN_EMAIL:
        is_admin = True
        
    current_user_id = session.get('user_id')
    
    # DEBUG: Log what we're sending to template
    logger.info(f"DEBUG: Rendering dashboard for user {session['user_id']}")
    logger.info(f"DEBUG: Folders count: {len(folders)}")
    logger.info(f"DEBUG: Files count: {len(files)}")
    logger.info(f"DEBUG: Is admin: {is_admin}")
    
    return render_template('dashboard.html', 
                         files=files, 
                         folders=folders,
                         current_folder=current_folder,
                         breadcrumbs=breadcrumbs,
                         is_admin=is_admin,
                         current_user_id=current_user_id)

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
        conn.execute(
            'INSERT INTO folders (name, user_id, parent_id) VALUES (?, ?, ?)',
            (folder_name, session['user_id'], parent_id)
        )
        user_base = get_user_base_path(conn, session['user_id'])
        rel_parent_path = ''
        if parent_id:
            rel_parent_path = get_folder_relative_path(conn, parent_id)
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

    file_part = request.files['file']
    if request.form.get('chunk_index') is not None and request.form.get('total_chunks') is not None and request.form.get('file_name') and request.form.get('upload_id'):
        try:
            chunk_index = int(request.form['chunk_index'])
            total_chunks = int(request.form['total_chunks'])
        except ValueError:
            return jsonify({'error': 'Invalid chunk indices'}), 400

        if chunk_index < 0 or total_chunks <= 0 or chunk_index >= total_chunks:
            return jsonify({'error': 'Invalid chunk indices'}), 400
        original_filename = secure_filename(request.form['file_name'])
        upload_id = secure_filename(request.form['upload_id'])
        folder_id_raw = request.form.get('folder_id')
        folder_id_val = None
        if folder_id_raw:
            try:
                folder_id_val = int(folder_id_raw)
            except ValueError:
                return jsonify({'error': 'Invalid folder ID'}), 400
        temp_dir = os.path.join(app.config['CHUNK_TEMP_FOLDER'], f"{session['user_id']}_{upload_id}")
        os.makedirs(temp_dir, exist_ok=True)
        part_path = os.path.join(temp_dir, f"part_{chunk_index:06d}")
        file_part.save(part_path)
        if chunk_index == total_chunks - 1:
            part_files = []
            for i in range(total_chunks):
                expected_path = os.path.join(temp_dir, f"part_{i:06d}")
                if not os.path.exists(expected_path):
                    return jsonify({'error': 'Missing chunks for assembly'}), 400
                part_files.append(expected_path)
            with get_db() as conn:
                user_base = get_user_base_path(conn, session['user_id'])
                rel_path = ''
                if folder_id_val is not None:
                    rel_path = get_folder_relative_path(conn, folder_id_val)
                if rel_path:
                    final_dir = os.path.join(user_base, rel_path)
                else:
                    final_dir = user_base
                os.makedirs(final_dir, exist_ok=True)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                unique_filename = f"{timestamp}_{original_filename}"
                final_path = os.path.join(final_dir, unique_filename)
                with open(final_path, 'wb') as outfile:
                    total_size = 0
                    for part_file in sorted(part_files):
                        with open(part_file, 'rb') as infile:
                            data = infile.read()
                            outfile.write(data)
                            total_size += len(data)
                for part_file in part_files:
                    try:
                        os.remove(part_file)
                    except OSError:
                        pass
                try:
                    os.rmdir(temp_dir)
                except OSError:
                    pass
                is_public_val = 0
                is_admin_user = False
                if session.get('user_id') == ADMIN_ID:
                    is_admin_user = True
                if ADMIN_EMAIL and session.get('user_email') == ADMIN_EMAIL:
                    is_admin_user = True
                if is_admin_user:
                    pub_flag = request.form.get('public') or request.form.get('is_public') or ''
                    if str(pub_flag).lower() in ['1', 'true', 'yes', 'on']:
                        is_public_val = 1
                conn.execute(
                    'INSERT INTO files (original_name, stored_name, user_id, folder_id, size, mimetype, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (original_filename, unique_filename, session['user_id'], folder_id_val, total_size, mimetypes.guess_type(original_filename)[0] or 'application/octet-stream', is_public_val)
                )
            logger.info(f"Chunked upload assembled - {original_filename}")
            return jsonify({'success': True, 'assembled': True})
        else:
            return jsonify({'success': True, 'assembled': False})

    folder_id = request.form.get('folder_id')
    filename = secure_filename(file_part.filename)
    if filename == '':
        return jsonify({'error': 'No selected file'}), 400
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    unique_filename = f"{timestamp}_{filename}"
    with get_db() as conn:
        user_base = get_user_base_path(conn, session['user_id'])
        rel_path = ''
        folder_id_int = None
        if folder_id:
            try:
                folder_id_int = int(folder_id)
                rel_path = get_folder_relative_path(conn, folder_id_int)
            except ValueError:
                return jsonify({'error': 'Invalid folder ID'}), 400
        if rel_path:
            upload_dir = os.path.join(user_base, rel_path)
        else:
            upload_dir = user_base
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, unique_filename)
        file_part.save(filepath)
        file_size = os.path.getsize(filepath)
        is_public_val = 0
        is_admin_user = False
        if session.get('user_id') == ADMIN_ID:
            is_admin_user = True
        if ADMIN_EMAIL and session.get('user_email') == ADMIN_EMAIL:
            is_admin_user = True
        if is_admin_user:
            pub_flag = request.form.get('public') or request.form.get('is_public') or ''
            if str(pub_flag).lower() in ['1', 'true', 'yes', 'on']:
                is_public_val = 1
        conn.execute(
            'INSERT INTO files (original_name, stored_name, user_id, folder_id, size, mimetype, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (filename, unique_filename, session['user_id'], folder_id_int, file_size, 
             mimetypes.guess_type(filename)[0] or 'application/octet-stream', is_public_val)
        )
    logger.info(f"Upload επιτυχές - {filename}")
    return jsonify({'success': True, 'assembled': True})

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND (user_id = ? OR is_public = 1)',
            (file_id, session['user_id'])
        ).fetchone()
    
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    
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
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND (user_id = ? OR is_public = 1)',
            (file_id, session['user_id'])
        ).fetchone()
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
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
    candidate_paths.append(os.path.abspath(os.path.join(user_base, file_info['stored_name'])))
    abs_path = None
    for p in candidate_paths:
        if os.path.isfile(p):
            abs_path = p
            break
    if abs_path is None:
        flash('File not found on server', 'error')
        return redirect(url_for('dashboard'))
    return send_file(
        abs_path,
        as_attachment=False,
        mimetype=file_info['mimetype']
    )

@app.route('/view/<int:file_id>')
def view_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND (user_id = ? OR is_public = 1)',
            (file_id, session['user_id'])
        ).fetchone()
    if not file_info:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
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


@app.route('/make_public/<int:file_id>', methods=['POST'])
def make_public(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    is_admin_user = False
    if session.get('user_id') == ADMIN_ID:
        is_admin_user = True
    if ADMIN_EMAIL and session.get('user_email') == ADMIN_EMAIL:
        is_admin_user = True
    if not is_admin_user:
        return jsonify({'error': 'Not authorized'}), 403
    with get_db() as conn:
        file_info = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        conn.execute('UPDATE files SET is_public = 1 WHERE id = ?', (file_id,))
    logger.info(f"File marked as public - ID {file_id}")
    return jsonify({'success': True})

@app.route('/make_folder_public/<int:folder_id>', methods=['POST'])
def make_folder_public(folder_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    # Μόνο ο admin μπορεί να κάνει φακέλους δημόσιους
    is_admin_user = False
    if session.get('user_id') == ADMIN_ID:
        is_admin_user = True
    if ADMIN_EMAIL and session.get('user_email') == ADMIN_EMAIL:
        is_admin_user = True
        
    if not is_admin_user:
        return jsonify({'error': 'Not authorized'}), 403
        
    with get_db() as conn:
        folder_info = conn.execute('SELECT * FROM folders WHERE id = ?', (folder_id,)).fetchone()
        if not folder_info:
            return jsonify({'error': 'Folder not found'}), 404
            
        conn.execute('UPDATE folders SET is_public = 1 WHERE id = ?', (folder_id,))
        
        # DEBUG: Verify the update worked
        updated_folder = conn.execute('SELECT * FROM folders WHERE id = ?', (folder_id,)).fetchone()
        logger.info(f"DEBUG: Folder {folder_id} is_public after update: {updated_folder['is_public']}")
        
    logger.info(f"Folder marked as public - ID {folder_id}")
    return jsonify({'success': True})

@app.route('/delete/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_ip = request.remote_addr
    
    with get_db() as conn:
        file_info = conn.execute(
            'SELECT * FROM files WHERE id = ? AND user_id = ?',
            (file_id, session['user_id'])
        ).fetchone()
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        user_base = get_user_base_path(conn, file_info['user_id'])
        rel_path_safe = ''
        rel_path_raw = ''
        if file_info['folder_id']:
            rel_path_safe = get_folder_relative_path(conn, file_info['folder_id'])
            rel_path_raw = get_folder_relative_path_raw(conn, file_info['folder_id'])
        candidate_paths = []
        if rel_path_raw:
            candidate_paths.append(os.path.join(user_base, rel_path_raw, file_info['stored_name']))
        if rel_path_safe:
            candidate_paths.append(os.path.join(user_base, rel_path_safe, file_info['stored_name']))
        if not file_info['folder_id']:
            candidate_paths.append(os.path.join(user_base, file_info['stored_name']))
        for fp in candidate_paths:
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except Exception:
                    pass
                break
        
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
    
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
        
        files = conn.execute('SELECT COUNT(*) as count FROM files WHERE folder_id = ?', (folder_id,)).fetchone()
        if files['count'] > 0:
            return jsonify({'error': 'Folder must be empty'}), 400
        
        subfolders = conn.execute('SELECT COUNT(*) as count FROM folders WHERE parent_id = ?', (folder_id,)).fetchone()
        if subfolders['count'] > 0:
            return jsonify({'error': 'Folder must be empty'}), 400
        
        conn.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
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
                continue
            except OSError:
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

@app.before_request
def check_email_verified():
    if 'user_id' in session and request.endpoint not in ['static', 'verify_email', 'verify_pending', 'logout', 'signin', 'resend_verification', 'verify_code']:
        with get_db() as conn:
            user = conn.execute('SELECT email_verified FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            if user and not user['email_verified'] and request.endpoint != 'verify_pending':
                return redirect(url_for('verify_pending'))

if __name__ == '__main__':
    print("=" * 40)
    print("File Server - Εκκίνηση...")
    print("=" * 40)
    print(f"Διεύθυνση: {app.config['BASE_URL']}")
    print(f"Φάκελος uploads: {app.config['UPLOAD_FOLDER']}")
    print(f"Βάση δεδομένων: {app.config['DATABASE']}")
    print("=" * 40)
    print("ΣΗΜΑΝΤΙΚΟ: Ρυθμίστε τα SMTP credentials στο server.py")
    print("για να λειτουργήσει το σύστημα επαλήθευσης email")
    print("=" * 40)
    
    import warnings
    warnings.filterwarnings("ignore")
    
    app.run(debug=False, host='0.0.0.0', port=5000)