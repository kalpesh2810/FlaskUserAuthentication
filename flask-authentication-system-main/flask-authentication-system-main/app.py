from flask import Flask, request, render_template, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

# Create database tables
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            return render_template('register.html', error='Email already exists')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Generate JWT token (here i changed my code for Authentication)
            token = jwt.encode(
                {
                    'user_id': user.id,
                    'email': user.email,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )

            token = token.decode('utf-8') if isinstance(token, bytes) else token

            return jsonify({'message': 'Login successful', 'token': token})
        else:
            return render_template('login.html', error='Invalid email or password')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
def dashboard():
    token = request.headers.get('Authorization')  # Expect token in Authorization header
    if not token:
        return jsonify({'message': 'Token is missing'}), 403

    try:
        # Decode the token
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(decoded_token['user_id'])

        if user:
            return render_template('dashboard.html', user=user)
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    return redirect('/login')

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('email', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
