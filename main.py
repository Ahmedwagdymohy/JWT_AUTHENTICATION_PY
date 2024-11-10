from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Secret key for JWT encoding and decoding
app.config['SECRET_KEY'] = 'your_secret_key'

# =====================
# Utility Functions
# =====================

def token_required(f):
    """
    A decorator to protect routes and ensure a valid token is provided.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')  # Get the token from the request headers
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['user']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        # Pass the current user to the endpoint
        return f(current_user, *args, **kwargs)
    return decorated

# =====================
# Routes
# =====================

@app.route('/login', methods=['POST'])
def login():
    """
    Endpoint to log in a user and return a JWT token.
    """
    auth = request.json  # Read JSON payload
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400

    username = auth['username']
    password = auth['password']

    # Dummy user validation (replace with actual database verification)
    if username != 'testuser' or password != 'testpass':
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Create token with an expiration time
    token = jwt.encode(
        {'user': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({'token': token})


@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    """
    A protected endpoint that requires a valid token.
    """
    return jsonify({'message': f'Welcome, {current_user}! This is a protected route.'})


@app.route('/refresh', methods=['POST'])
@token_required
def refresh_token(current_user):
    """
    Endpoint to refresh the token for an authenticated user.
    """
    new_token = jwt.encode(
        {'user': current_user, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

    return jsonify({'token': new_token})


@app.route('/logout', methods=['POST'])
def logout():
    """
    Endpoint to simulate logout (JWT can't truly invalidate tokens without tracking).
    """
    return jsonify({'message': 'Logout successful. Just stop using your token!'})


# =====================
# Running the App
# =====================

if __name__ == '__main__':
    app.run(debug=True)
