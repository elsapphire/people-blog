from flask import Flask, request, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, login_required, LoginManager, current_user, logout_user  # login_required
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPassword, VerificationCodeForm, ChangePassword
from flask_gravatar import Gravatar
from functools import wraps

import os
from send_email import SendEmail, joined_list

# import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

login_manager = LoginManager()
# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL1', "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_author = relationship('User', back_populates='comments')

    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')

    text = db.Column(db.Text, nullable=False)


# with app.app_context():
# #     db.create_all()

coming_from_code = False


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, user=current_user, logged_in=current_user.is_authenticated)


@app.route('/sign-up', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data == form.password_confirmation.data:
            password = generate_password_hash(
                password=form.password.data,
                method='pbkdf2:sha256',
                salt_length=10
            )

            user = User.query.filter_by(email=form.email.data).first()
            if user is None:
                new_user = User(
                    name=form.name.data,
                    email=form.email.data,
                    password=password,
                )

                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("You've already signed up with that email. Log in instead")
                return redirect(url_for('login'))
        else:
            flash("The passwords don't match")
            return redirect(url_for('register'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        present_user = User.query.filter_by(email=form.email.data).first()
        # print(present_user)
        if present_user is None:
            flash('That email does not exist. Try again')
            return redirect(url_for('login'))

        checking = check_password_hash(present_user.password, form.password.data)
        if checking:
            login_user(present_user)

            return redirect(url_for('get_all_posts'))

        else:
            flash('Password incorrect. Try again')
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))

        flash('You need to log in or sign up to comment')
        return redirect(url_for('login'))
    return render_template("post.html", form=form, post=requested_post, user=current_user,
                           logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.id == 1:
            print(f'it is {current_user.id}')
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    # response = requests.get(url='https://api.npoint.io/c25d7dfd2f5302121001')
    # posts = response.json()
    # for post in posts:
    #     new_post = BlogPost(
    #         title=post['title'],
    #         subtitle=post['subtitle'],
    #         body=post['body'],
    #         author=current_user,
    #         date=date.today().strftime("%B %d, %Y"),
    #         img_url='img url'
    #     )
    #     db.session.add(new_post)
    #     db.session.commit()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data.title(),
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/forgot-password', methods=['POST', 'GET'])
def forgot_password():
    global coming_from_code
    coming_from_code = False
    form = ForgotPassword()
    all_users = db.session.query(User).all()
    all_email = [user.email for user in all_users]
    if form.validate_on_submit():
        typed_email = form.email.data
        if typed_email in all_email:
            user_email = User.query.filter_by(email=typed_email).first()
            user_name = user_email.name
            email = user_email.email
            return render_template('found_account.html', email=email, name=user_name)
        else:
            flash("That email doesn't exist. Try again")
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html', form=form, coming_from_code=coming_from_code,
                           logged_in=current_user.is_authenticated)


@app.route('/reset-password/<name>/<email>', methods=['POST', 'GET'])
def get_code(name, email):
    form = VerificationCodeForm()
    send_email = SendEmail(email, name)
    if request.method == 'GET':
        send_email.send_code()
    global coming_from_code
    coming_from_code = True

    code = joined_list

    print(code)

    if form.validate_on_submit():
        typed_code = int(form.code.data)
        if typed_code == code:
            return redirect(url_for('change_password', email=email))
        else:
            flash('The code is incorrect. Please try again')

    return render_template('forgot_password.html', form=form, coming_from_code=coming_from_code)


@app.route('/change-password/<email>', methods=['POST', 'GET'])
def change_password(email):
    form = ChangePassword()
    if form.validate_on_submit():
        if form.password.data == form.confirmation.data:
            password = generate_password_hash(
                password=form.password.data,
                method='pbkdf2:sha256',
                salt_length=10
            )

            account_to_update = User.query.filter_by(email=email).first()
            print(account_to_update.password)
            if password == account_to_update.password:
                flash("You've already used that password. Type a new one")
                return redirect(url_for('change_password'))
            account_to_update.password = password
            db.session.commit()

            login_user(account_to_update)
            return redirect(url_for('get_all_posts'))
        else:
            flash("The passwords don't match")
    return render_template('change_password.html', form=form)


@app.route("/delete-comment/<int:post_id>/<int:comment_id>", methods=["GET", "POST"])
@login_required
def delete_comment(post_id, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
