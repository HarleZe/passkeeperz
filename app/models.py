import sqlite3, base64
from flask import current_app

def get_db_connection():
    conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            aes_key TEXT NOT NULL
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            iv TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS shared_links (
            id TEXT PRIMARY KEY,
            password_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (password_id) REFERENCES passwords(id)
        )
    ''')


    conn.commit()
    conn.close()

def get_user_aes_key(user_id):
    conn = get_db_connection()
    row = conn.execute('SELECT aes_key FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if row:
        return base64.b64decode(row['aes_key'])
    return None
