import datetime

from flask import Flask
from flask import jsonify
from flask import request

from flask_jwt_extended import create_access_token, create_refresh_token,get_jwt_identity, jwt_required, JWTManager

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

class Users(db.Model):
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.String(230), nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User {}>'.format(self.name)

    def setPassword(self, password):
        self.password = generate_password_hash(password)

    def checkPassword(self, password):
        return check_password_hash(self.password, password)


# # Setup the Flask-JWT-Extended extension
# jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def login():
    try:
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        user = Users.query.filter_by(name=username).first()
        if not user :
            return jsonify({"msg": "Username not found!"}),403
        if not user.checkPassword(password):
            return jsonify({"msg": "Password incorrect!"}),403
        
        # if username != "test" or password != "test":
        #     return jsonify({"msg": "Bad username or password"}), 401
        data = {
            'username':user.name,
            'password':user.password
        }
        expires = datetime.timedelta(days=1)
        expires_refresh = datetime.timedelta(days=3)
        access_token = create_access_token(data, fresh=True, expires_delta=expires)
        refresh_token = create_refresh_token(data, expires_delta=expires_refresh)
        return jsonify(
            {
            "data": data,
            "token_access": access_token,
            "token_refresh": refresh_token,
        }), 200
    except Exception as e:
        return jsonify(str(e)),403


@app.route("/register", methods=["POST"])
def register():
    try:
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        new_user = Users(name = username)
        new_user.setPassword(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg":"successfully created a user"}),200
    except Exception as e:
        return jsonify(str(e)),403

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()
    # with app.app_context():
    #     db.create_all()
    # db.init_app(app)
    # app.run()