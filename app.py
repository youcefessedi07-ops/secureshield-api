import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)
# In a real application, keep this secret and store it in an environment variable!
app.config['SECRET_KEY'] = 'secureshield_super_secret_key_2026'
bcrypt = Bcrypt(app)

# Task 6: Defensive Logging
# Logs unauthorized attempts to security.log
logging.basicConfig(filename='security.log', level=logging.WARNING,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Task 5: Token Revocation
# In-memory blacklist for simplicity (use Redis or a DB table in production)
token_blacklist = set()

# --- Database Setup (SQLite) ---
def get_db_connection():
    conn = sqlite3.connect('secureshield.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Middleware / Decorators ---

# Task 3: Token Validation
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        if token in token_blacklist:
            return jsonify({'message': 'Token has been revoked! Please log in again.'}), 401

        try:
            # Validates signature and expiration automatically
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# Task 4 & 6: Admin Access Check & Defensive Logging
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'Admin':
            # Log the 403 attempt
            logging.warning(f"Unauthorized Admin access attempt to {request.path} by user: {current_user.get('username')}")
            return jsonify({'message': 'Forbidden: Admin access required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# --- API Routes ---

# Task 1: Secure Password Storage
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'User') # Defaults to 'User'

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    # Salt and hash password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, hashed_password, role))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists!'}), 400

# Task 2: JWT Issuance
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    # Check if user exists and password matches the hash
    if user and bcrypt.check_password_hash(user['password'], password):
        # Generate JWT with username and role
        token = jwt.encode({
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.now(timezone.utc) + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200

    return jsonify({'message': 'Invalid credentials!'}), 401

# Task 5: Token Revocation (Blacklisting)
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers['Authorization'].split()[1]
    token_blacklist.add(token) # Add token to blacklist
    return jsonify({'message': 'Successfully logged out.'}), 200

# Task 4: Accessible by User and Admin
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'message': f"Welcome to your profile, {current_user['username']}!",
        'role': current_user['role']
    }), 200

# Task 4: Accessible ONLY by Admin
@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user(current_user, id):
    conn = get_db_connection()
    # Check if user exists before deleting
    user_to_delete = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    if not user_to_delete:
        return jsonify({'message': 'User not found!'}), 404
        
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'message': f'User with id {id} deleted successfully.'}), 200

if __name__ == '__main__':
    app.run(debug=True)