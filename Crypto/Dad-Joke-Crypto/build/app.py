import os
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from utils import (
    generate_parameters, 
    requires_auth, 
    generate_pow_challenge, 
    check_pow, 
    PowSolutionForm
)
from gevent.pywsgi import WSGIServer
from gevent import monkey
monkey.patch_all()
app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.urandom(32)
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(32)

def ensure_parameters():
    if not session.get('parameters_generated'):
        params = generate_parameters(session)
        session['parameters_generated'] = True

def get_current_params() -> dict:
    return {
        "alice": {
            "n": session.get('n'),
            "vka": session.get('vka'),
            "vkakb": session.get('vkakb')
        },
        "bob": {
            "vkb": session.get('vkb')
        },
        "ciphertext": session.get('ciphertext')
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/pow", methods=["GET", "POST"])
def pow_challenge():
    form = PowSolutionForm()
    if request.method == "GET":
        challenge_str = generate_pow_challenge(session)
        return render_template("pow.html", challenge=challenge_str, form=form)
    if form.validate_on_submit():
        user_solution = form.solution.data.lower()  
        challenge_str = session.get('pow_challenge', '')
        if not challenge_str:
            return render_template(
                "pow.html", 
                form=form, 
                challenge=generate_pow_challenge(session),
                error="No challenge found, please try again."
            )
        if check_pow(challenge_str, user_solution):
            session['auth'] = True
            ensure_parameters()
            return redirect(url_for('challenge_route'))
        
        return render_template(
            "pow.html", 
            form=form,
            challenge=challenge_str,
            error="Incorrect proof-of-work solution."
        )
    
    
    return render_template(
        "pow.html", 
        form=form,
        challenge=session.get('pow_challenge', generate_pow_challenge(session)),
        error="Invalid input. Please check your solution format."
    )
    
@app.route("/challenge")
@requires_auth
def challenge_route():
    try:
        ensure_parameters()
        params = get_current_params()
        accept = request.headers.get('Accept', '')
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    if 'application/json' in accept:
        return jsonify(params)
    else:
        return render_template("challenge.html", params=params)

@app.route("/flag")
@requires_auth
def flag():
    ensure_parameters()
    c = session.get('ciphertext')
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept:
        return jsonify({
            "encrypted_flag": c, 
            "hint": "Cracking this might be easier than factoring my sense of humor!"
        })
    else:
        return render_template("flag.html", ciphertext=c)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    http_server = WSGIServer(('0.0.0.0', 6969), app)
    http_server.serve_forever()
    
