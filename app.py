from flask import Flask, render_template, request, redirect, url_for, flash, session, abort

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime,timedelta
from flask import session
from flask_jwt_extended import create_refresh_token



from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)



app = Flask(__name__)

api = Api(app)

app.config["JWT_SECRET_KEY"] = "my-super-long-secret-key-for-jwt-authentication-2026"

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]

jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):

    jti = jwt_payload["jti"]

    token = TokenBlocklist.query.filter_by(jti=jti).first()

    return token is not None


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship("Post", backref="user", lazy=True)
  
     # <-- Add this
     # <-- Add this


class Post(db.Model):

    id = db.Column(db.Integer, primary_key=True)   # Sr No
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)


    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class TokenBlocklist(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    jti = db.Column(db.String(100), nullable=False, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)



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

# jwt authentication



class RegisterAPI(Resource):

    def post(self):

        data = request.get_json()

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return {"msg": "Missing data"}, 400

        if User.query.filter_by(email=email).first():
            return {"msg": "User already exists"}, 409

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        user = User(email=email, password=hashed)

        db.session.add(user)
        db.session.commit()

        return {"msg": "User registered successfully"}, 201


# from flask_jwt_extended import create_refresh_token


class LoginAPI(Resource):

    def post(self):

        data = request.get_json()

        if not data:
            return {"msg": "Missing JSON"}, 400

        email = data.get("email")
        password = data.get("password")

        user = User.query.filter_by(email=email).first()

        if not user:
            return {"msg": "Invalid credentials"}, 401

        if not bcrypt.check_password_hash(user.password, password):
            return {"msg": "Invalid credentials"}, 401

        access = create_access_token(
            identity=str(user.id),
            additional_claims={"is_admin": user.is_admin}
        )

        refresh = create_refresh_token(identity=str(user.id))

        return {
            "access_token": access,
            "refresh_token": refresh,
            "user_id": user.id,
            "email": user.email
        }


class ProfileAPI(Resource):

    @jwt_required()
    def get(self):

        user_id = int(get_jwt_identity())  # convert back

        user = User.query.get_or_404(user_id)

        return {
            "id": user.id,
            "email": user.email,
            "is_admin": user.is_admin,
            "created_at": user.created_at.strftime("%Y-%m-%d")
        }



class PostListAPI(Resource):

    @jwt_required()
    def get(self):

        user_id = int(get_jwt_identity())

        posts = Post.query.filter_by(user_id=user_id).all()

        result = []

        for p in posts:
            result.append({
                "id": p.id,
                "title": p.title,
                "desc": p.desc,
                "date": p.date.strftime("%Y-%m-%d")
            })

        return result

class AddPostAPI(Resource):

    @jwt_required()
    def post(self):

        data = request.get_json()

        post = Post(
            title=data["title"],
            desc=data["desc"],
            user_id=int(get_jwt_identity())
        )

        db.session.add(post)
        db.session.commit()

        return {"msg": "Post added"}, 201

class PostAPI(Resource):

    @jwt_required()
    def put(self, id):
        
        user_id = int(get_jwt_identity())
        post = Post.query.get_or_404(id)


        if post.user_id != user_id:
          return {"msg": "Not allowed"}, 403

        data = request.get_json()

        post.title = data["title"]
        post.desc = data["desc"]

        db.session.commit()

        return {"msg": "Updated"}


    @jwt_required()
    def delete(self, id):

        user_id = int(get_jwt_identity())

        post = Post.query.get_or_404(id)

        if post.user_id != user_id:
            return {"msg": "Access denied"}, 403

        db.session.delete(post)
        db.session.commit()

        return {"msg": "Deleted"}
    
    from flask_jwt_extended import jwt_required, get_jwt_identity


class RefreshAPI(Resource):

    @jwt_required(refresh=True)
    def post(self):

        user_id = get_jwt_identity()

        new_access = create_access_token(identity=user_id)

        return {"access_token": new_access}
from flask_jwt_extended import get_jwt


class LogoutAPI(Resource):

    @jwt_required()
    def post(self):

        jti = get_jwt()["jti"]

        blocked = TokenBlocklist(jti=jti)

        db.session.add(blocked)
        db.session.commit()

        return {"msg": "Logged out successfully"}
    

from flask_jwt_extended import verify_jwt_in_request, get_jwt


def admin_required(fn):

    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):

        verify_jwt_in_request()

        claims = get_jwt()

        if not claims.get("is_admin"):
            return {"msg": "Admin only!"}, 403

        return fn(*args, **kwargs)

    return wrapper

class AdminUsersAPI(Resource):

    @admin_required
    def get(self):

        users = User.query.all()

        data = []

        for u in users:
            data.append({
                "id": u.id,
                "email": u.email,
                "is_admin": u.is_admin
            })

        return data






api.add_resource(RegisterAPI, "/api/register")
api.add_resource(LoginAPI, "/api/login")
api.add_resource(ProfileAPI, "/api/profile")

api.add_resource(PostListAPI, "/api/posts")
api.add_resource(AddPostAPI, "/api/posts/add")
api.add_resource(PostAPI, "/api/posts/<int:id>")
api.add_resource(RefreshAPI, "/api/refresh")
api.add_resource(LogoutAPI, "/api/logout")
api.add_resource(AdminUsersAPI, "/api/admin/users")









if __name__ == "__main__":
    app.run(debug=True,port=9000)
