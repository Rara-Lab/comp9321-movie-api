from flask import Flask,request
from flask_restx import Api,Resource,fields
from flask_sqlalchemy import SQLAlchemy 
# using python to operate database instead of SQL 定义表+查数据
from flask_jwt_extended import JWTManager,jwt_required,get_jwt_identity,create_access_token
# create token, implement login system (manage who can login)
# @jwt_require() Automatic protection interface (login required)
# get_jwt_identity() get the information form token
from passlib.hash import bcrypt
# cannot store plaintext passwords
from datetime import datetime,timezone
# time tool
from functools import wraps
import pandas as pd
import ast
# 0.
app = Flask(__name__)

# 1.Setting parameters
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///movie_api.db"
# database location: The database uses SQLite, and the database file name is movie_api.db(///:relative path,portable)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Do not track object modification signals(consume more resource)
app.config["JWT_SECRET_KEY"] = "secret-key"

# 2.
db = SQLAlchemy(app)
# apply sql to flask app
jwt = JWTManager(app)
# connect to login system

# 3.
authorizations = {
    "Bearer": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "Paste your JWT token here with: Bearer <token>"
    }
}
api = Api(
    app,
    version="1.0",
    title="Movie REST API",
    description="COMP9321 Assignment 2 API",
    doc="/",
    authorizations=authorizations,
    security="Bearer"
)
ns = api.namespace("test",description="Test endpoints")
auth_ns = api.namespace("auth",description = "Authentication endpoints")
accounts_ns = api.namespace("accounts",description = "accounts endpoints")
movies_ns = api.namespace("movies", description="Movie endpoints")
# 4.define login model
login_input_model = auth_ns.model(
    "LoginInput",
    {
        "username":fields.String(required = True,description = "The username"),
        "password":fields.String(required = True,description = "The password"),
    }   
)
login_output_model = auth_ns.model(
    "LoginOutput",
    {
        "access_token":fields.String(required = True,description = "JWT access token"),
        "message":fields.String(required = True,description = "Login result message"),
    }   
)
account_output_model = accounts_ns.model(
    "AccountOutput",{
        "id":fields.Integer(description = "User ID"),
        "username": fields.String(description = "username"),
        "role" : fields.String(description = "User role"),
        "is_active" : fields.Boolean(description = "Whether the account is active"),
        "created_at" : fields.String(description = "Account creation time"),
    }
)
account_status_model = accounts_ns.model(
    "Status",{
        "is_active" : fields.Boolean(required = True,description = "Whether the account is active"),
    }
)
account_create_model = accounts_ns.model(
    "AccountCreateInput",
    {
        "username": fields.String(required=True, description="New username"),
        "password": fields.String(required=True, description="New password"),
    }
)

cast_output_model = api.model(
    "CastOutput",
    {
        "cast_id": fields.Integer(description="Cast ID"),
        "name": fields.String(description="Cast name"),
        "character": fields.String(description="Character name"),
        "gender": fields.Integer(description="Gender"),
        "order": fields.Integer(description="Cast order"),
    }
)
crew_output_model = api.model(
    "CrewOutput",
    {
        "crew_id": fields.Integer(description="Crew ID"),
        "name": fields.String(description="Crew name"),
        "job": fields.String(description="Job title"),
        "department": fields.String(description="Department"),
        "gender": fields.Integer(description="Gender"),
    }
)
movie_output_model = api.model(
    "MovieOutput",
    {
        "id": fields.Integer(description="Movie ID"),
        "title": fields.String(description="Movie title"),
        "overview": fields.String(description="Movie overview"),
        "release_date": fields.String(description="Release date"),
        "vote_average": fields.Float(description="Average vote"),
        "vote_count": fields.Integer(description="Vote count"),
        "popularity": fields.Float(description="Popularity"),
        "runtime": fields.Integer(description="Runtime"),
        "original_language": fields.String(description="Original language"),
        "original_title": fields.String(description="Original title"),
        "status": fields.String(description="Movie status"),
        "tagline": fields.String(description="Movie tagline"),
        "casts": fields.List(fields.Nested(cast_output_model)),
        "crews": fields.List(fields.Nested(crew_output_model)),
    }
)
# 5.define a database table
class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    # i:INTEGER PRIMARY KEY
    username = db.Column(db.String(80),unique=True,nullable=False)
    password_hash = db.Column(db.String(255),nullable=False)
    role = db.Column(db.String(20),nullable=False)
    is_active = db.Column(db.Boolean,default=True)
    created_at = db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc))
    # prevent time from being fixed at the moment of app startup
    def set_password(self,password):
        self.password_hash = bcrypt.hash(password)
    def check_password(self,password):
        return bcrypt.verify(password,self.password_hash)
    def get_current_user():
        current_user_id = get_jwt_identity()
        user = db.session.get(User,int(current_user_id))
        return user
class Movie(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    title = db.Column(db.String(255), nullable=False)
    overview = db.Column(db.Text)
    release_date = db.Column(db.String(50))
    vote_average = db.Column(db.Float)
    vote_count = db.Column(db.Integer)
    popularity = db.Column(db.Float)
    runtime = db.Column(db.Integer)
    original_language = db.Column(db.String(20))
    original_title = db.Column(db.String(255))
    status = db.Column(db.String(50))
    tagline = db.Column(db.String(255))
    casts = db.relationship("Cast",backref="movie",cascade="all,delete-orphan")
    crews = db.relationship("Crew", backref="movie", cascade="all, delete-orphan")
class Cast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"), nullable=False)
    cast_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    character = db.Column(db.String(255))
    gender = db.Column(db.Integer)
    order = db.Column(db.Integer)
class Crew(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"), nullable=False)
    crew_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    job = db.Column(db.String(255))
    department = db.Column(db.String(255))
    gender = db.Column(db.Integer)

# 6.define functions
def create_default_users():
    admin = User.query.filter_by(username="admin").first()
    if admin is None:
        admin = User(username="admin",role = "Admin",is_active=True)
        admin.set_password("admin")
        db.session.add(admin)
    user = User.query.filter_by(username="user").first()
    if user is None:
        user = User(username="user",role = "User",is_active=True)
        user.set_password("user")
        db.session.add(user)
    db.session.commit()
def get_current_user():
    user_id = get_jwt_identity()
    user = db.session.get(User,int(user_id))
    return user
def admin_required(func):
    @wraps(func)
    @jwt_required()
    def wrapper(*args,**kwargs):
        user = get_current_user()
        if user is None:
            accounts_ns.abort(404,"User not found")
        if user.role !="Admin":
            accounts_ns.abort(403,"Admin access required.")
        if not user.is_active:
            accounts_ns.abort(403,"This account is deactivated.")
        return func(*args,**kwargs)
    return wrapper
def import_movies_data():
    if Movie.query.first() is not None:
        return
    movies_df = pd.read_csv("movies.csv")
    credits_df = pd.read_csv("credits.csv")
    merged_df = pd.merge(movies_df, credits_df,left_on="id",right_on="movie_id",how="inner")
    for _, row in merged_df.iterrows():
        movie = Movie(
            id=int(row["id"]),
            title=row.get("title_x") if pd.notna(row.get("title_x")) else None,
            overview=row.get("overview") if pd.notna(row.get("overview")) else None,
            release_date=str(row.get("release_date")) if pd.notna(row.get("release_date")) else None,
            vote_average=float(row["vote_average"]) if pd.notna(row.get("vote_average")) else None,
            vote_count=int(row["vote_count"]) if pd.notna(row.get("vote_count")) else None,
            popularity=float(row["popularity"]) if pd.notna(row.get("popularity")) else None,
            runtime=int(row["runtime"]) if pd.notna(row.get("runtime")) else None,
            original_language=row.get("original_language") if pd.notna(row.get("original_language")) else None,
            original_title=row.get("original_title") if pd.notna(row.get("original_title")) else None,
            status=row.get("status") if pd.notna(row.get("status")) else None,
            tagline=row.get("tagline") if pd.notna(row.get("tagline")) else None,
        )
        db.session.add(movie)
        db.session.flush()
        cast_list = []
        crew_list = []
        if pd.notna(row.get("cast")):
            try:
                cast_list = ast.literal_eval(row["cast"])
            except (ValueError, SyntaxError):
                cast_list = []
        if pd.notna(row.get("crew")):
            try:
                crew_list = ast.literal_eval(row["crew"])
            except (ValueError, SyntaxError):
                crew_list = []
        for cast_member in cast_list:
            cast_obj = Cast(
                movie_id=movie.id,
                cast_id=cast_member.get("cast_id", 0),
                name=cast_member.get("name", ""),
                character=cast_member.get("character"),
                gender=cast_member.get("gender"),
                order=cast_member.get("order"),
            )
            db.session.add(cast_obj)
        for crew_member in crew_list:
            crew_obj = Crew(
            movie_id=movie.id,
            crew_id=crew_member.get("id", 0),
            name=crew_member.get("name", ""),
            job=crew_member.get("job"),
            department=crew_member.get("department"),
            gender=crew_member.get("gender"),
            )
            db.session.add(crew_obj)
    db.session.commit()
# 7.
@ns.route("/ping")
class PingResource(Resource):
    def get(self):
        return {"message":"Hello"},200

@auth_ns.route("/login")
class LoginResource(Resource):
    @auth_ns.expect(login_input_model, validate=True)
    @auth_ns.marshal_with(login_output_model)
    def post(self):
        data = request.get_json()
        username = data["username"]
        password = data["password"]
        user = User.query.filter_by(username=username).first()
        if user is None:
            auth_ns.abort(401,"Invalid username or password.")
        if not user.check_password(password):
            auth_ns.abort(401,"Invalid username or password.")
        if not user.is_active:
            auth_ns.abort(403,"This account is deactivated.")
        access_token = create_access_token(identity=str(user.id))
        # check username\passsword\active
        return {
            "access_token":access_token,
            "message":"Login successful"
        },200
@accounts_ns.route("/me")
class MeResource(Resource):
    @jwt_required()
    @accounts_ns.marshal_with(account_output_model)
    def get(self):
        current_user_id = get_jwt_identity()
        # creating token used user.id, get_jet_identity() got user.id
        user = db.session.get(User,int(current_user_id))
        if user is None:
            accounts_ns.abort(404, "User not found.")
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
        }, 200
@accounts_ns.route("")
class AccountListResource(Resource):
    @accounts_ns.doc(security="Bearer")
    @accounts_ns.marshal_list_with(account_output_model)
    # multiple accounts
    @admin_required
    def get(self):
        users = User.query.order_by(User.id).all()
        return [
            {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
            }
            for user in users
        ],200
    @accounts_ns.doc(security = "Bearer")
    @accounts_ns.expect(account_create_model,validate=True)
    @accounts_ns.marshal_with(account_output_model)
    @admin_required
    def post(self):
        data = request.get_json()
        username = data["username"].strip()
        password = data["password"]
        user = User.query.filter_by(username=username).first() 
        if user is not None:
            accounts_ns.abort(409, "Username already exists.")
        new_user = User(
            username=username,
            role="User",
            is_active=True
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return {
            "id": new_user.id,
            "username": new_user.username,
            "role": new_user.role,
            "is_active": new_user.is_active,
            "created_at": new_user.created_at.isoformat(),
        },201
        # create new accounts
@accounts_ns.route("/<int:user_id>/status")
class AccountStatusResource(Resource):
    @accounts_ns.doc(security = "Bearer")
    @accounts_ns.expect(account_status_model,validate=True)
    @accounts_ns.marshal_with(account_output_model)
    @admin_required
    def patch(self,user_id):
        user = db.session.get(User,user_id)
        if user is None:
            accounts_ns.abort(404, "User not found.")
        if user.username == "admin":
            accounts_ns.abort(403, "The admin account cannot be deactivated.")
        data = request.get_json()
        user.is_active = data["is_active"]
        db.session.commit()
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat(),
        }, 200 
@accounts_ns.route("/<int:user_id>")
class AccountResource(Resource):
    @accounts_ns.doc(security = "Bearer")
    @admin_required
    def delete(self,user_id):
        user = db.session.get(User,user_id)
        if user is None:
            accounts_ns.abort(404, "User not found.")
        if user.username == "admin":
            accounts_ns.abort(403, "The admin account cannot be deleted.")
        current_user = get_current_user()
        if current_user is not None and current_user.id == user.id:
            accounts_ns.abort(403, "You cannot delete your own account.")
        db.session.delete(user)
        db.session.commit()
        return {
            "message":f"User '{user.username}' deleted successfully."
        },200

@movies_ns.route("/<int:movie_id>")
class MovieResource(Resource):
    @movies_ns.marshal_with(movie_output_model)
    def get(self, movie_id):
        movie = db.session.get(Movie, movie_id)
        if movie is None:
            movies_ns.abort(404, "Movie not found.")

        return {
            "id": movie.id,
            "title": movie.title,
            "overview": movie.overview,
            "release_date": movie.release_date,
            "vote_average": movie.vote_average,
            "vote_count": movie.vote_count,
            "popularity": movie.popularity,
            "runtime": movie.runtime,
            "original_language": movie.original_language,
            "original_title": movie.original_title,
            "status": movie.status,
            "tagline": movie.tagline,
            "casts": [
                {
                    "cast_id": cast.cast_id,
                    "name": cast.name,
                    "character": cast.character,
                    "gender": cast.gender,
                    "order": cast.order,
                }
                for cast in movie.casts
            ],
            "crews": [
                {
                    "crew_id": crew.crew_id,
                    "name": crew.name,
                    "job": crew.job,
                    "department": crew.department,
                    "gender": crew.gender,
                }
                for crew in movie.crews
            ],
        }, 200

# 8.
with app.app_context():
    db.create_all()
    create_default_users()
    import_movies_data()
    print("Movies:", Movie.query.count())
    print("Casts:", Cast.query.count())
    print("Crews:", Crew.query.count())
if __name__=="__main__":
    app.run(debug=True,port=5000)




