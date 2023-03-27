from flask import Flask, render_template, redirect, url_for, request, flash, abort, Blueprint
# lib tha handles the main db actions: create, insert, update, delete
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
# lib required to handle the login and logout process
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# lib required to generate and compare hashes
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
# lib required to create decorators
from functools import wraps
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
# libs required to make the relationship between the tables
from sqlalchemy import Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
import os

Base = declarative_base()
#
# # CREATE THE BLUEPRINT
# main = Blueprint('main', __name__)


# CREATE THE FLASK APP
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    return app


app = create_app()
ckeditor = CKEditor(app)


# CONNECT TO DB
db = SQLAlchemy(app)


# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# GRAVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# USER LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(db.Model, UserMixin, Base):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="user")
    comment = relationship("Comment", back_populates="user")


# CONFIGURE TABLE
class BlogPost(db.Model, Base):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # user relationship: child
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship("User", back_populates="posts")
    # comment relationship: parent
    post_comments = relationship("Comment", back_populates="blog_post")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    # user relationship: child
    user_id = db.Column(Integer, ForeignKey('user.id'))
    user = relationship("User", back_populates="comment")
    # post relationship: child
    post_id = db.Column(Integer, ForeignKey('blog_post.id'))
    blog_post = relationship("BlogPost", back_populates="post_comments")


def admin_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return function(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    db.create_all()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm(request.form)
    if request.method == "POST" and register_form.validate():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with this email. Log in instead.")
            return redirect("/login")
        else:
            new_user = User()
            new_user.name = str(register_form.name.data,)
            new_user.email = str(register_form.email.data,)
            new_user.password = str(generate_password_hash(
                password=register_form.password.data,
                method='sha256',
                salt_length=8
            ))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect('/')

    return render_template("register.html", form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    message = "Email or password incorrect. Try again."
    # validate
    if request.method == "POST" and login_form.validate():
        # check email
        user = User.query.filter_by(email=str(login_form.email.data)).first()
        if not user:
            flash(message)
            return redirect("/login")
        elif check_password_hash(user.password, login_form.password.data):
            # login ok
            login_user(user)
            return redirect('/')
        else:
            # password incorrect
            flash(message)

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    comment_form = CommentForm(request.form)
    requested_post = BlogPost.query.filter_by(id=post_id).first()
    if requested_post:
        return render_template("post.html", post=requested_post, form=comment_form)
    else:
        return "<p>Woops!, something went wrong</p>"


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# CREATE A NEW POST
@app.route('/new-post', methods=['GET', 'POST'])
@login_required
# @admin_required
def add_new_post():
    post_form = CreatePostForm(request.form)
    title_action = "New Post"
    if request.method == "POST" and post_form.validate():
        date = datetime.datetime.now()
        new_post = BlogPost(
            title=post_form.title.data,
            subtitle=post_form.subtitle.data,
            author=current_user.name,
            img_url=post_form.img_url.data,
            body=post_form.body.data,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=post_form, title=title_action)


# EDIT A POST
@app.route('/edit-post/<post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post_to_edit = BlogPost.query.filter_by(id=post_id).first()

    if request.method == "POST":
        modified_form = CreatePostForm(request.form)
        if modified_form.validate():
            post_to_edit.title = modified_form.title.data
            post_to_edit.subtitle = modified_form.subtitle.data
            post_to_edit.author = modified_form.author.data
            post_to_edit.img_url = modified_form.img_url.data
            post_to_edit.body = modified_form.body.data
            db.session.commit()
            return redirect('/')
    else:
        post_form = CreatePostForm(
            id=post_to_edit.id,
            title=post_to_edit.title,
            subtitle=post_to_edit.subtitle,
            author=post_to_edit.author,
            img_url=post_to_edit.img_url,
            body=post_to_edit.body,
            date=post_to_edit.date
        )
        title_action = "Edit Post"
        return render_template('make-post.html', form=post_form, title=title_action, id=post_id)


@app.route('/delete-post/<post_id>')
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.filter_by(id=post_id).first()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect('/')


# ADD A COMMENT TO A POST
@app.route('/add-comment', methods=['GET', 'POST'])
@login_required
def add_comment():
    comment_form = CommentForm(request.form)
    post_id = request.args.get("post_id")
    if request.method == "POST" and comment_form.validate():
        new_comment = Comment(
            text=str(comment_form.comment.data),
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
