from flask_security.forms import RegisterForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length, ValidationError
from models import User


class ExtendedRegisterForm(RegisterForm):
    """Extended registration form with username field."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64, message='Username must be between 3 and 64 characters')
    ])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken. Please choose a different one.')
