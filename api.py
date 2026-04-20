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
    
# 8.
with app.app_context():
    db.create_all()
    create_default_users()
if __name__=="__main__":
    app.run(debug=True,port=10000)




