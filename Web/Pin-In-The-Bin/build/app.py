from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
from functools import wraps
from datetime import datetime, timedelta
import re
from hashlib import sha3_256
import secrets
from random  import randint
from utils import requires_pow, generate_pow_challenge, check_pow
from forms import PowSolutionForm, PinVerificationForm,  LoginForm
from gevent.pywsgi import WSGIServer
from gevent import monkey; monkey.patch_all()

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(seconds=240)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(32)



FLAG = open("flag.txt", "r").read().strip()
CORRECT_PIN = str(randint(1000, 10000-1))
POW_DIFFICULTY = 2  
print(f"CORRECT_PIN: {CORRECT_PIN}")

USERS = {
    "admin@secureauth.com": {
        "password": "151cae882ab83e13d3ea17647f975b25e351083e61d930dbaf238f801d87769f",
        "reset_token_expiry": None,
        "failed_attempts": 0,
        "lockout_until": None,
        "pin": None
    }
}

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

@app.route('/')
@requires_pow
def index():
    return render_template('index.html')

@app.route('/pow', methods=['GET', 'POST'])
def pow_challenge():
    if session.get('pow_solved'):
        return redirect(url_for('index'))
    form = PowSolutionForm()
    challenge = session.get('pow_challenge')
    if not challenge or request.method == 'GET':
        challenge = generate_pow_challenge(session)
        session['pow_attempts'] = 0
    if request.method == 'POST':
        if form.validate_on_submit():
            solution = form.solution.data
            # 50 attempts limit
            session['pow_attempts'] = session.get('pow_attempts', 0) + 1
            if session['pow_attempts'] > 50:
                session.pop('pow_challenge', None)
                flash('Too many attempts. Please try again with a new challenge.', 'error')
                return redirect(url_for('pow_challenge'))
            if check_pow(challenge, solution, POW_DIFFICULTY):
                session['pow_solved'] = True
                session['pow_timestamp'] = datetime.now().timestamp() 
                session.pop('pow_challenge', None)
                session.pop('pow_attempts', None)
                flash('Proof of Work challenge solved successfully!', 'success')
                return redirect(url_for('index'))
            
            flash('Invalid solution. Please try again.', 'error')
    
    return render_template('pow.html', 
                         form=form, 
                         challenge=challenge,
                         difficulty=POW_DIFFICULTY)

@app.route('/login', methods=['GET', 'POST'])
@requires_pow
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data.lower()
        password = form.password.data 
        user = USERS.get(email)
        if user:
            if user['lockout_until'] and user['lockout_until'] > datetime.now():
                remaining_time = (user['lockout_until'] - datetime.now()).seconds // 60
                flash(f'Account is locked. Please try again in {remaining_time} minutes.', 'error')
                return render_template('login.html', form=form)
            if sha3_256(password.encode()).hexdigest() == user['password']:
                session.permanent = True
                session['user_email'] = email
                
                flash('Successfully logged in!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials.', 'error')

    return render_template('login.html', form=form)

@app.route('/logout')
@requires_pow
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
@requires_pow
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').lower()
        if not email or not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html')
        user = USERS.get(email)
        if user:
            user['reset_token'] = os.urandom(16).hex()
            user['reset_token_expiry'] = datetime.now() + timedelta(hours=1)
            user['pin'] = str(randint(1000, 10000-1))
            flash('If an account exists with this email, you will receive reset instructions.', 'success')
            return redirect(url_for('login'))
        else:
            flash('If an account exists with this email, you will receive reset instructions.', 'success')
            return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET'])
@requires_pow
def reset(token):
    for email, user in USERS.items():
        if user['reset_token'] == token:
            if user['reset_token_expiry'] > datetime.now():
                session['reset_email'] = email
                return redirect(url_for('verify_pin'))
            else:
                flash('Reset link has expired. Please request a new one.', 'error')
                return redirect(url_for('forgot_password'))
    flash('Invalid reset link.', 'error')
    return redirect(url_for('login'))

@app.route('/verify-pin', methods=['GET', 'POST'])
@requires_pow
def verify_pin():
    form = PinVerificationForm()
    if form.validate_on_submit():
        pin = form.pin.data
        if int(pin) == int(CORRECT_PIN):            
            flash(f"PIN Found! {FLAG}")
            return render_template('success.html', flag=FLAG)
        else:
            flash('Incorrect PIN.', 'error')
    return render_template('pin.html', form=form)

if __name__ == '__main__':
    http_server = WSGIServer(('0.0.0.0', 5000), app)
    http_server.serve_forever()
    