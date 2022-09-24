from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

#### LOGIN MANAGER ####
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # RELATIONSHIPS #

    #one post can be written by a lot of authors
    posts = relationship("BlogPost", back_populates="author")
    #one comment can bee written by lot of authors
    comments = relationship('Comment',back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # RELATIONSHIPS #

    # new column in the blogpost table that takes the user.id from the User table and by doing this we know which user wrote the article
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Create reference to the User object, the "posts" refers to the posts' property in the User class.
    #user can do a lot of posts
    author = db.relationship("User", back_populates="posts")
    #תגובה אחת יכולה להיכתב בהרבה פוסטים
    comments = relationship('Comment',back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # RELATIONSHIPS #
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    comment_author = relationship("User",back_populates="comments")
    # we can know what comment was written for each post by the id of each post
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    #בפןסט אחד יכולות להיכתב הרבה תגובות
    parent_post = relationship("BlogPost",back_populates="comments")
# Create all the tables in the database
db.create_all()


########## FUNCTIOUNS ###########
def admin_only(f):
    '''This function check if the function that it get each time which is the f prameter if the user id is 1 if it is so the user has all the accesses
    else it will return error 403'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args,**kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,current_user=current_user)


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # if the email that the user typed in the form is equal to the email that exits in the data base
        if User.query.filter_by(email=form.email.data).first():
            # it means that the user already exists
            flash(("You've already signed up with that email, log in instead!"))
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        # login_user(new_user)
        return redirect(url_for('login'))
    return render_template("register.html",form=form)




@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # the email and password that the user typed in the login form
        email = form.email.data
        password = form.password.data
        # if all the data was good and no empty fields

        # user = to the user with the attributes with the current email from the data base -- gives us the email,name and hash password
        user = User.query.filter_by(email=email).first()
        #if the user with the email above does not exsits in the data base
        if not user:
            flash('The Email does not exist please try again')
            return redirect(url_for('login'))

        # if the email and password are correct and everything was good
        if check_password_hash(user.password, password):
            login_user(user)
            # the user transfer to the secrets page
            return redirect(url_for('get_all_posts'))

        # if the hash password from the data base != the hash password from the form
        else:
            flash('Password incorrect please try again')
            return redirect(url_for('login'))
    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.Comment.data,
            author_id=current_user.id,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post,form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET','POST'])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))






if __name__ == "__main__":
    app.run(debug=True)
