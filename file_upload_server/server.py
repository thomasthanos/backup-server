from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
from datetime import datetime
import mimetypes
import sqlite3
from contextlib import contextmanager
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['DATABASE'] = 'data/fileserver.db'

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
            
            CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
            CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
            CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);
        ''')

init_db()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    return redirect(url_for('dashboard'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Παίρνουμε την IP του χρήστη
        user_ip = request.remote_addr
        
        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_email'] = user['email']
                # ΝΕΟ: Προσθήκη IP στο μήνυμα επιτυχίας
                logger.info(f"Σύνδεση επιτυχής - {email} από IP: {user_ip}")
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # ΝΕΟ: Προσθήκη IP στο μήνυμα αποτυχίας
                logger.info(f"Αποτυχημένη σύνδεση - {email} από IP: {user_ip}")
                flash('Invalid email or password', 'error')
    
    return render_template('signin.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name', email.split('@')[0])
    
    with get_db() as conn:
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing:
            flash('Email already registered', 'error')
            return redirect(url_for('signin'))
        
        conn.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                    (email, generate_password_hash(password), name))
        
        user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        session['user_id'] = user['id']
        session['user_email'] = email
        
    logger.info(f"Νέος χρήστης - {email}")
    flash('Account created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Εδώ θα μπορούσατε να προσθέσετε λογική για αποστολή email reset
        # Για τώρα, απλά εμφανίζουμε ένα μήνυμα
        
        flash('If an account with that email exists, a password reset link has been sent.', 'success')
        return redirect(url_for('signin'))
    
    return render_template('request-password-reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Αυτό είναι ένα placeholder - θα χρειαστεί πραγματική λογική για token validation
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset-password.html')
        
        # Εδώ θα μπορούσατε να ενημερώσετε τον κωδικό στη βάση δεδομένων
        flash('Password has been reset successfully!', 'success')
        return redirect(url_for('signin'))
    
    return render_template('reset-password.html')

@app.route('/logout')
def logout():
    email = session.get('user_email', 'Unknown')
    session.clear()
    logger.info(f"Αποσύνδεση - {email}")
    flash('Logged out successfully', 'success')
    return redirect(url_for('signin'))

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
        
        # Get folders in current location
        folders = conn.execute(
            'SELECT * FROM folders WHERE user_id = ? AND parent_id IS ? ORDER BY name',
            (session['user_id'], folder_id)
        ).fetchall()
        
        # Get files in current location
        files = conn.execute(
            'SELECT * FROM files WHERE user_id = ? AND folder_id IS ? ORDER BY uploaded DESC',
            (session['user_id'], folder_id)
        ).fetchall()
    
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
        conn.execute(
            'INSERT INTO folders (name, user_id, parent_id) VALUES (?, ?, ?)',
            (folder_name, session['user_id'], parent_id)
        )
    
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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        file.save(filepath)
        file_size = os.path.getsize(filepath)
        
        if folder_id:
            folder_id = int(folder_id)
        else:
            folder_id = None
        
        with get_db() as conn:
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
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_name'])
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
    # Build an absolute path to the requested file. Without an absolute
    # path, Flask may fail to locate the file in different working
    # directories. If the file is missing, redirect back with an error.
    rel_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_name'])
    filepath = os.path.abspath(rel_path)
    if not os.path.isfile(filepath):
        flash('File not found on server', 'error')
        return redirect(url_for('dashboard'))
    # Serve the file inline without forcing a download. Avoid specifying
    # download_name to maintain compatibility with older Flask versions.
    return send_file(
        filepath,
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
        
        # Delete physical file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_name'])
        if os.path.exists(filepath):
            os.remove(filepath)
        
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
        
        conn.execute('DELETE FROM folders WHERE id = ?', (folder_id,))
    
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

if __name__ == '__main__':
    print("=" * 40)
    print("File Server - Εκκίνηση...")
    print("=" * 40)
    print(f"Διεύθυνση: http://localhost:5000")
    print(f"Φάκελος uploads: {app.config['UPLOAD_FOLDER']}")
    print(f"Βάση δεδομένων: {app.config['DATABASE']}")
    print("=" * 40)
    
    # Απενεργοποίηση debug messages
    import warnings
    warnings.filterwarnings("ignore")
    
    app.run(debug=False, host='0.0.0.0', port=5000)