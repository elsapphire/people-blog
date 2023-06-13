import requests
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Choose A Password', validators=[DataRequired()])
    password_confirmation = PasswordField('Type The Password Again', validators=[DataRequired()])
    submit = SubmitField('SIGN ME UP!')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('LET ME IN!')


class CommentForm(FlaskForm):
    comment = CKEditorField('Comment', validators=[DataRequired()])
    submit = SubmitField('SUBMIT COMMENT')


class ForgotPassword(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    submit = SubmitField('Submit')


class VerificationCodeForm(FlaskForm):
    code = StringField('Code', validators=[DataRequired()])
    submit = SubmitField('Submit')


class ChangePassword(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirmation = PasswordField('New Password Again', validators=[DataRequired()])
    submit = SubmitField('Submit')


# response = requests.get(url='https://api.npoint.io/c25d7dfd2f5302121001')
# posts = response.json()
# for post in posts:
#     print(post['title'])
