from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ganti dengan kunci rahasia yang lebih kuat
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Model Pengguna


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    date_of_birth = db.Column(db.String(20), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    origin = db.Column(db.String(120), nullable=False)
    religion = db.Column(db.String(50), nullable=False)


# Membuat database dan tabel
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = user.username
            return redirect(url_for('profile'))
        else:
            return "Username atau password salah!", 401
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        date_of_birth = request.form['date_of_birth']
        phone_number = request.form['phone_number']
        origin = request.form['origin']
        religion = request.form['religion']

        if User.query.filter_by(username=username).first():
            return "Username sudah terdaftar!", 400

        new_user = User(username=username,
                        password=generate_password_hash(password),
                        full_name=full_name,
                        date_of_birth=date_of_birth,
                        phone_number=phone_number,
                        origin=origin,
                        religion=religion)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/profile')
def profile():
    if 'logged_in' in session:
        return render_template('profile.html')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()  # Menghapus semua data sesi
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
