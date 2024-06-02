from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .models import User
from . import db
from flask_limiter import Limiter


# Create a blueprint named 'auth'
auth = Blueprint("auth", __name__)

# Initialize the rate limiter
limiter = Limiter(key_func=get_remote_address)


@auth.route("/register", methods=["POST"])
def register():
    """
    Expects payload with 'username', 'password', and optional 'role'.
    Checks if both username and password are provided, then check
    if the username already exists. After that,
    create a new user with hashed password and saves it to the database.
    Returns a success message or an error message.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    # Ensure both username and password are provided
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Check if the user already exists
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"msg": "User already exists"}), 409

    # Create a new user and save to the database
    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully"}), 201


@auth.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Rate limiting: max 5 requests per minute
def login():
    """
    Expects a JSON payload with 'username' and 'password'.
    Checks if both username and password are provided, then validates
    the user's credentials and generates a JWT access token if credentials are valid.
    Returns the access token or an error message.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Ensure both username and password are provided
    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Check if the user exists and the password is correct
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Invalid credentials"}), 401

    # Generate a JWT access token
    access_token = create_access_token(
        identity={"username": username, "role": user.role}
    )
    return jsonify(access_token=access_token), 200


@auth.route("/protected", methods=["GET"])
@jwt_required()  # Require a valid JWT to access this endpoint
def protected():
    """
    Requires a valid JWT access token to access.
    Retrieves the current user's identity from the JWT.
    Returns the user's identity.
    """
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


    #alternative for input validation
  #       if len(username) <= 3:
   #                 flash('Username must be greater than 3 characters', category='error')
   #             elif len(password) < 7:
  #                     flash('Too short you dingus.', category= 'error') 
    #            elif len(email) < 4:
   #                    flash('email must be greater than 4 characters', category='error')
