from flask import Flask, render_template, redirect, request, url_for, session, flash
import mysql.connector
from flask_bcrypt import Bcrypt
from wtforms import Form, StringField, PasswordField, validators

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Config
db_config = {
    'user': 'your_username',
    'password': 'your_password',
    'host': 'localhost',
    'database': 'login_system'
}

bcrypt = Bcrypt(app)

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users(username, password) VALUES(%s, %s)", (username, password))
        conn.commit()
        cursor.close()
        conn.close()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_candidate = form.password.data

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            password = user['password']
            if bcrypt.check_password_hash(password, password_candidate):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('home'))
            else:
                error = 'Invalid login'
                return render_template('login.html', form=form, error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'logged_in' in session:
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
