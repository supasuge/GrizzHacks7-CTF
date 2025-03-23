import secrets
from hashlib import sha256
import string
from functools import wraps
from flask import session, redirect, url_for, flash
from datetime import datetime, timedelta



def requires_pow(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('pow_solved'):
            flash('Please solve the Proof of Work challenge first.', 'error')
            return redirect(url_for('pow_challenge'))
        pow_timestamp = session.get('pow_timestamp')
        if not pow_timestamp or datetime.fromtimestamp(pow_timestamp) < datetime.now() - timedelta(hours=1):
            session.clear()
            flash('Your PoW session expired. Please solve again.', 'error')
            return redirect(url_for('pow_challenge'))
        return f(*args, **kwargs)
    return wrapper


def generate_pow_challenge(session):
    if session.get('pow_challenge'):
        return session.get('pow_challenge')
    challenge_str = secrets.token_hex(8) 
    session['pow_challenge'] = challenge_str
    return challenge_str

def check_pow(challenge_str, user_solution, difficulty=2):
    target = '0' * difficulty
    h = sha256((challenge_str + user_solution).encode()).hexdigest()
    return h.startswith(target)

