import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from neti_beta_02.app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
