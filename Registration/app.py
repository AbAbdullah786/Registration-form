from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.handlers.sha2_crypt import sha512_crypt
from wtforms.validators import ValidationError

app = Flask(__name__, template_folder='template')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/registration'
app.config['SECRET_KEY'] = 'SECRET_KEY'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256),)
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = User.query.filter_by(email=email).first()
            pas = user.password

            if sha512_crypt.verify(password, pas):
                session['email'] = email
                # return render_template('new.html')
                return redirect(url_for('myapp'))
            else:
                flash('invalid email / password')
                return redirect(url_for('login'))
                # return 'login not successfully'
        except:
            flash('try again except block')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['POST','GET'])
def register():
    if request.method == 'POST':
        name = request.form['username']
        n_email = request.form['email']
        password = request.form['password']
        if len(password) < 5:
            raise ValidationError('Password must have atleast 5 characters')
        enc_password = sha512_crypt.encrypt(password)

        entry = User(username=name, email=n_email, password=enc_password)
    
        try:
            c_email = User.query.filter_by(email=n_email).first()
            if not c_email:
                db.session.add(entry)
                db.session.commit()
                flash('registration done')
                return redirect(url_for('login'))
            else:                                     
                flash('email exist')
                return redirect(url_for('register'))
        except:
            flash('try agian')
            return redirect(url_for('register'))
    return render_template('register.html')
    
@app.route('/logout')
def logout():
    session.pop('email',None)
    db.session.delete()
    return render_template('index.html')

@app.route('/app')
def myapp():
    return render_template('new.html')

  
if __name__ == '__main__':
    app.run(debug=True)
