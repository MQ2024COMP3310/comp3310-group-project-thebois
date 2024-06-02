import pytest
from myapp import create_app, db
from myapp.models import User
import os


# setting up test client
@pytest.fixture(scope="module")
def test_client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI")
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret")

    with app.test_client() as testing_client:
        with app.app_context():
            db.create_all()
            yield testing_client
            db.drop_all()


"""
Generic test cases for user registration. Still barebone, need to adjust to fit the actual implementation
"""

auth_register = "/auth/register"


def test_successful_registration(test_client):
    response = test_client.post(
        auth_register, json={"username": "test", "password": "Passwd@1"}
    )
    assert response.status_code == 201
    assert response.get_json() == {"msg": "User created successfully"}


def test_registration_missing_data(test_client):
    response = test_client.post(auth_register, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt"})
    assert response.status_code == 400
    assert response.get_json() == {"msg": "Username and password required"}


def test_duplicate_registration(test_client):
    test_client.post(
        auth_register, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    response = test_client.post(
        auth_register, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    assert response.status_code == 409
    assert response.get_json() == {"msg": "User already exists"}


"""
Generic test cases for user login. Still barebone, need to adjust to fit the actual implementation
"""

auth_login = "/auth/login"


def test_successful_login(test_client):
    test_client.post(
        "/auth/register", json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    response = test_client.post(
        auth_login, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    assert response.status_code == 200
    assert "access_token" in response.get_json()


def test_login_invalid_credentials(test_client):
    response = test_client.post(
        auth_login, json={"username": "wronguser", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    assert response.get_json() == {"msg": "Invalid credentials"}


def test_login_missing_data(test_client):
    response = test_client.post(auth_login, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt"})
    assert response.status_code == 400
    assert response.get_json() == {"msg": "Username and password required"}


def test_rate_limiting(test_client):
    for _ in range(5):
        response = test_client.post(
            auth_login, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
        )
    response = test_client.post(
        auth_login, json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    assert response.status_code == 429  # Too many requests


"""
Generic test cases for protected routes. Still barebone, need to adjust to fit the actual implementation
"""


def test_protected_route_access(test_client):
    test_client.post(
        "/auth/register", json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    login_response = test_client.post(
        "/auth/login", json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    token = login_response.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = test_client.get("/auth/protected", headers=headers)
    assert response.status_code == 200
    assert response.get_json() == {
        "logged_in_as": {"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "role": "user"}
    }


def test_protected_route_no_token(test_client):
    response = test_client.get("/auth/protected")
    assert response.status_code == 401


def test_protected_route_invalid_token(test_client):
    headers = {"Authorization": "Bearer invalidtoken"}
    response = test_client.get("/auth/protected", headers=headers)
    assert response.status_code == 422


def test_role_required(test_client):
    test_client.post(
        "/auth/register",
        json={"username": "adminuser", "password": "adminpassword", "role": "admin"},
    )
    login_response = test_client.post(
        "/auth/login", json={"username": "adminuser", "password": "adminpassword"}
    )
    token = login_response.get_json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = test_client.post("/some_admin_route", headers=headers)
    assert response.status_code == 200

    login_response_user = test_client.post(
        "/auth/login", json={"username": "alkshjdfhgjawerkluthaesfdrkljvhadfkljvgaesfhrgilkouawerhglokiaewrfhgloiawerihgt", "password": "awelkrjgh asdfjkhvbdzcjvkhasefdhggiouaWERGYHTILwraeughfailkwderfughAWRLIOUG"}
    )
    token_user = login_response_user.get_json()["access_token"]
    headers_user = {"Authorization": f"Bearer {token_user}"}

    response_user = test_client.post("/some_admin_route", headers=headers_user)
    assert response_user.status_code == 403
