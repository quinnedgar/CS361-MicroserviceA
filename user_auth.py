from flask import Flask, request, jsonify
import sqlite3
import bcrypt 
from datetime import datetime, timedelta
import jwt
import re


SECRET = 'this_should_not_be_hardcoded_in_real_deployment'
##Actual implementation could use .env or similar
##Only used on line ____ for authentication token

app = Flask(__name__)

################################# Database Establishment ################################# 

db_name = "user_database.db"  # SQLite database file

def init_db():
    # Connect to SQLite database
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Unique ID for each user
            username TEXT NOT NULL,  -- Username column
            email TEXT NOT NULL,  -- Email column
            password TEXT NOT NULL  -- Password column
        )
    """)
    conn.commit()
    conn.close()

init_db()  # Initialize the database when the app starts

####################################################################################

################################# Authentication Token Logic #######################

def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=1) 
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return token

def decode_token(token):
    try:
        decoded_token = jwt.decode(token, SECRET, algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return {"error": "Token expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

#########################################################Change where needed#########

@app.route('/login', methods=['POST'])
def login_user():
    body = request.json

    username = body.get('username')
    unhashed_pw = body.get('password')

    if not username or not unhashed_pw:
        return jsonify({"Incomplete Request Error": "Enter all input fields (username, password)"}), 400

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        stored_pw = user[2]  
        user_id = user[0]

        if bcrypt.checkpw(unhashed_pw.encode('utf-8'), stored_pw.encode('utf-8')):
            return jsonify({"message": "Login successful", "auth_token": generate_token(user_id)}), 200
        else:
            return jsonify({"error": "Incorrect password"}), 401
    else:
        return jsonify({"Login Request Fail": "User not located"}), 400


@app.route('/register', methods=['POST'])
def register_user():
    body = request.json
    username = body.get('username')
    email = body.get('email')
    unhashed_pw = body.get('password')
    confirm_password = body.get('confirm_password')

    if not username or not email or not unhashed_pw or not confirm_password:
        return jsonify({"Incomplete Request Error": "Enter all input fields"}), 400

    if confirm_password != unhashed_pw:
        return jsonify({"Registration Fail": "Passwords must match"}), 400

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return jsonify({"Registration Fail": "Invalid email format"}), 400

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
    existing_user = cursor.fetchone()
    conn.close()

    if existing_user:
        return jsonify({"Registration Fail": "Username or email already exists"}), 400

    hashed_pw = bcrypt.hashpw(unhashed_pw.encode(), bcrypt.gensalt())

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw.decode('utf-8')))
    conn.commit()
    conn.close()

    return jsonify({"Registration Success": f"User {username} registered"}), 201


if __name__ == '__main__':
    app.run(debug=True)

