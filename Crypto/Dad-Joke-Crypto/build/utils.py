import secrets, string
from random import randint
from Crypto.Util.number import getPrime, GCD, inverse, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from flask import session
from functools import wraps
from flask import redirect, url_for
from typing import Dict
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError

def validate_solution(form, field):
    """Validator to ensure input contains only lowercase letters and numbers"""
    try:
        value = field.data.lower()
        allowed_chars = set(string.ascii_lowercase + string.digits)
        if not set(value).issubset(allowed_chars):
            raise ValidationError('Solution can only contain lowercase letters and numbers')
    except Exception:
        raise ValidationError('Invalid solution format')


class PowSolutionForm(FlaskForm):
    """Form for submitting Proof of Work solutions with strict validation"""
    solution = StringField('Solution',
        validators=[
            DataRequired(message="Solution is required"),
            Length(min=1, max=20, message="Solution must be between 1 and 20 characters"),
            validate_solution
        ]
    )
    submit = SubmitField('Submit Solution')

        
def generate_parameters(session) -> Dict[str, any]:
    try:
        p: int = getPrime(512)
        q: int = getPrime(512)
        n: int = p * q
        r: int = randint(1, n)
        v: int = (p * r) % n
        k_A: int = randint(1, n)
        while GCD(k_A, n) != 1:
            k_A = randint(1, n)
        vka: int = (v * k_A) % n
        k_B: int = randint(1, n)
        while GCD(k_B, n) != 1:
            k_B = randint(1, n)
        vkakb: int = (vka * k_B) % n
        vkb: int = (vkakb * inverse(k_A, n)) % n
        # Load flag from file
        with open('flag.txt', 'rb') as f:
            FLAG = f.read().strip()
        key: bytes = sha256(long_to_bytes(v)).digest()
        iv: bytes = secrets.token_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        encrypted_flag: bytes = cipher.encrypt(pad(FLAG, AES.block_size))
        c: str = (iv + encrypted_flag).hex()
        session['p'] = str(p)
        session['q'] = str(q)
        session['n'] = str(n)
        session['vka'] = str(vka)
        session['vkakb'] = str(vkakb)
        session['vkb'] = str(vkb)
        session['ciphertext'] = c

        return {
            "alice": {
                "n": str(n),
                "vka": str(vka),
                "vkakb": str(vkakb)
            },
            "bob": {
                "vkb": str(vkb)
            }
        }
    except Exception as e:
        raise e

def requires_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('auth'):
            return redirect(url_for('pow_challenge'))
        return f(*args, **kwargs)
    return wrapper

def generate_pow_challenge(session):
    challenge_str = secrets.token_hex(8) 
    session['pow_challenge'] = challenge_str
    return challenge_str

def check_pow(challenge_str, user_solution, difficulty=4):
    if not isinstance(challenge_str, str) or not isinstance(user_solution, str):
        return False
    allowed_chars = set(string.ascii_lowercase + string.digits)
    if not set(user_solution.lower()).issubset(allowed_chars):
        return False

    target = '0' * difficulty
    h = sha256((challenge_str + user_solution).encode()).hexdigest()
    return h.startswith(target)

