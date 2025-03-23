from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, Regexp



class ForgotPasswordForm(FlaskForm):
    """Form for the 'forgot password' page."""
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Please enter a valid email address"),
            Length(max=100, message="Email must be less than 100 characters"),
            Regexp(
                r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$',
                message="Please enter a valid email address"
            )
        ]
    )
    submit = SubmitField("Send Reset Instructions")


class LoginForm(FlaskForm):
    email = StringField(
        'Email',
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Please enter a valid email address"),
            Length(max=100, message="Email must be < 100 chars")
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required"),
            Length(min=8, message="Password must be >= 8 chars")
        ]
    )
    submit = SubmitField('Log In')

class PinVerificationForm(FlaskForm):
    """Form for PIN verification"""
    pin = StringField(
        'Security PIN',
        validators=[
            DataRequired(message="PIN is required"),
            Length(min=4, max=4, message="PIN must be exactly 4 digits"),
            Regexp(r'^\d{4}$', message="PIN must be exactly 4 digits")
        ]
    )
    submit = SubmitField('Verify PIN')

class PowSolutionForm(FlaskForm):
    """
    Form for PoW solutions. This puzzle specifically wants an 8‑char
    alphanumeric string (a-z0-9), matching the typical solver code.
    """
    solution = StringField(
        'Solution',
        validators=[
            DataRequired(message="Solution is required"),
            Length(min=8, max=8, message="Solution must be exactly 8 characters."),
            Regexp(r'^[a-zA-Z0-9]{8}$', message="Solution must be 8 alphanumeric characters (a-z, A-Z, 0-9).")
        ]
    )
    submit = SubmitField('Submit Solution')
