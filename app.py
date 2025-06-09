from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os

app = Flask(__name__, 
    static_folder='.',
    template_folder='.')
app.secret_key = os.urandom(24)  # Secure random secret key

def get_db_connection():
    conn = sqlite3.connect('salt2source.db')
    conn.row_factory = sqlite3.Row
    return conn

# Add these routes to your existing app.py

# Add this to your init_db() function
def init_db():
    conn = sqlite3.connect('salt2source.db')
    c = conn.cursor()
    
    # Your existing tables...
    
    # Water sources table
    c.execute('''
        CREATE TABLE IF NOT EXISTS water_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Add these new routes
@app.route('/api/water-sources', methods=['GET', 'POST'])
def water_sources():
    if request.method == 'POST':
        data = request.json
        conn = sqlite3.connect('salt2source.db')
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO water_sources (name, type, description, latitude, longitude)
            VALUES (?, ?, ?, ?, ?)
        ''', (data['name'], data['type'], data['description'], data['latitude'], data['longitude']))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    else:  # GET request
        conn = sqlite3.connect('salt2source.db')
        c = conn.cursor()
        c.execute('SELECT * FROM water_sources ORDER BY created_at DESC')
        sources = [{
            'id': row[0],
            'name': row[1],
            'type': row[2],
            'description': row[3],
            'latitude': row[4],
            'longitude': row[5],
            'created_at': row[6]
        } for row in c.fetchall()]
        conn.close()
        return jsonify(sources)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([username, email, password]):
            flash('All fields are required')
            return render_template('signup.html')
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Check if username or email exists
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                      (username, email))
            if c.fetchone() is not None:
                flash('Username or email already exists')
                return render_template('signup.html')
            
            # Create new user
            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'An error occurred: {str(e)}')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            flash('Please provide both username and password')
            return render_template('login.html')
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash('Login successful!')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password')
        except sqlite3.Error as e:
            flash(f'An error occurred: {str(e)}')
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Hash the password
        hashed_password = generate_password_hash(data['password'])
        
        c.execute('''
            INSERT INTO users (username, password, email, full_name, phone, address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['username'], hashed_password, data['email'],
              data['full_name'], data.get('phone'), data.get('address')))
        
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        
        return jsonify({'success': True, 'user_id': user_id})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Username or email already exists'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('SELECT * FROM users WHERE username = ?', (data['username'],))
    user = c.fetchone()
    
    if user and check_password_hash(user[2], data['password']):
        # Record successful login
        c.execute('''
            INSERT INTO login_history (user_id, ip_address, success)
            VALUES (?, ?, ?)
        ''', (user[0], request.remote_addr, True))
        
        session['user_id'] = user[0]
        session['username'] = user[1]
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    # Record failed login attempt
    if user:
        c.execute('''
            INSERT INTO login_history (user_id, ip_address, success)
            VALUES (?, ?, ?)
        ''', (user[0], request.remote_addr, False))
        conn.commit()
    
    conn.close()
    return jsonify({'success': False, 'error': 'Invalid credentials'})

@app.route('/api/water-sources', methods=['GET', 'POST'])
def water_sources():
    if request.method == 'POST':
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Not logged in'})
        
        data = request.json
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('''
            INSERT INTO water_sources (name, latitude, longitude, type, description, added_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['name'], data['latitude'], data['longitude'],
              data['type'], data['description'], session['user_id']))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    else:  # GET request
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM water_sources')
        sources = c.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'sources': [{
                'id': s[0],
                'name': s[1],
                'latitude': s[2],
                'longitude': s[3],
                'type': s[4],
                'description': s[5]
            } for s in sources]
        })

# Example of how to query data:
@app.route('/api/water-sources')
def get_water_sources():
    conn = get_db_connection()
    sources = conn.execute('SELECT * FROM water_sources').fetchall()
    conn.close()
    return jsonify([dict(source) for source in sources])

# Example of how to insert data:
@app.route('/api/water-sources', methods=['POST'])
def add_water_source():
    data = request.json
    conn = get_db_connection()
    conn.execute('INSERT INTO water_sources (name, type, latitude, longitude, quality) VALUES (?, ?, ?, ?, ?)',
                 (data['name'], data['type'], data['latitude'], data['longitude'], data['quality']))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Source added successfully'})
    
    conn.close()
    return jsonify({'message': 'Source added successfully'})

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS water_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            quality INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Call this when starting the app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
    app.run(debug=True, host='0.0.0.0', port=5000)