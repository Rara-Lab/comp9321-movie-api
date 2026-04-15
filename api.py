from flask import Flask,request
from flask_restx import Api,Resource,fields
from flask_sqlalchemy import SQLAlchemy 
# using python to operate database instead of SQL 定义表+查数据
from flask_jwt_extended import JWTManager,jwt_required,get_jwt_identity,create_access_token
# create token, implement login system (manage who can login)
# @jwt_require() Automatic protection interface (login required)
from passlib.hash import bcrypt
# cannot store plaintext passwords
from datetime import datetime,timezone
# time tool

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
jwt = JWTManager()
# connect to login system

# 3.

api = Api(
    app,
    version="1.0",
    title="Movie REST API",
    description="COMP9321 Assignment 2 API",
    doc="/"
)
ns = api.namespace("test",description="Test endpoints")
auth_ns = api.namespace("auth",description = "Authentication endpoints")

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

# 6.default user
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

# 8.
with app.app_context():
    db.create_all()
    create_default_users()
if __name__=="__main__":
    app.run(debug=True,port=5001)




