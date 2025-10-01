import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-for-neti-beta-02'
    API_KEY = os.environ.get('API_KEY')
    # Add any other configuration variables here
