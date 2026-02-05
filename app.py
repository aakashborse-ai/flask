from flask import Flask, render_template, request, redirect, url_for, flash, session, abort

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask import session


app = Flask(__name__)

# Secret key (for session & flash)
app.config["SECRET_KEY"] = "mysecretkey"

# Database (SQLite)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# ------------------ Database Model ------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)   # <-- Add this


class Post(db.Model):

    id = db.Column(db.Integer, primary_key=True)   # Sr No
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ Create DB ------------------

with app.app_context():
    db.create_all()


# ------------------ Routes ------------------

@app.route("/", methods=["GET", "POST"])
def login():
    # Clear old session on visiting login page
    session.clear()

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_email"] = user.email
            return redirect(url_for("dashboard"))

        flash("Invalid Email or Password", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "warning")
            return redirect(url_for("register"))

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = User(
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful! Please Login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")
@app.route("/add", methods=["GET", "POST"])
def add_post():

    if request.method == "POST":

        title = request.form["title"]
        desc = request.form["desc"]

        new_post = Post(
            title=title,
            desc=desc
        )

        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("dashboard"))

    return render_template("add.html")



@app.route("/dashboard")
def dashboard():

    page = request.args.get("page",1,type=int)
    search = request.args.get("q","")

    query = Post.query

    if search:
        query = query.filter(
            Post.title.contains(search)
        )

    posts = query.order_by(Post.id.desc()) \
                 .paginate(page=page, per_page=5)

    return render_template("dashboard.html", posts=posts)


def login_required(func):

    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):
            flash("Please login first", "warning")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper

@app.route("/logout")
def logout():

    session.clear()

    flash("Logged out successfully", "success")

    return redirect(url_for("login"))


# Edit Post
@app.route("/edit/<int:id>", methods=["GET","POST"])
def edit_post(id):

    post = Post.query.get_or_404(id)

    if request.method == "POST":
        post.title = request.form["title"]
        post.desc = request.form["desc"]

        db.session.commit()
        flash("Updated Successfully","success")

        return redirect("/dashboard")

    return render_template("edit.html", post=post)


# Delete Post
@app.route("/delete/<int:id>")
def delete_post(id):

    post = Post.query.get_or_404(id)

    db.session.delete(post)
    db.session.commit()

    flash("Deleted Successfully","danger")

    return redirect("/dashboard")

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect("/")

    user = User.query.get(session["user_id"])

    return render_template("profile.html", user=user)

@app.route("/admin")
def admin_panel():
    if "user_id" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if not user.is_admin:
        abort(403)

    users = User.query.all()
    return render_template("admin.html", users=users)







if __name__ == "__main__":
    app.run(debug=True,port=9000)
