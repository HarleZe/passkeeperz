import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev')
    DATABASE_PATH = 'database/passwords.db'
