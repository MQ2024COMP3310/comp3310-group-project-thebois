from flask import (
    Blueprint,
    render_template,
    request,
    flash,
    redirect,
    url_for,
    send_from_directory,
    current_app,
    make_response,
)
from .models import Photo
from sqlalchemy import asc, text
from . import db
import os
from flask_jwt_extended import jwt_required, get_jwt_identity
from functools import wraps

main = Blueprint("main", __name__)

"""
 Decorator to enforce role-based access control.
    Args:
        role (str): The role required to access the endpoint (e.g., 'admin').
    Returns:
        function: The decorated function with role-based access control enforced.
"""


def role_required(role):
    # Wrapper function to enforce role-based access control.
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        # decorator function to perform the role check.
        def decorator(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user["role"] != role:
                return jsonify({"msg": "Access denied"}), 403
            return fn(*args, **kwargs)

        return decorator

    return wrapper


# This is called when the home page is rendered. It fetches all images sorted by filename.
@main.route("/")
def homepage():
    photos = db.session.query(Photo).order_by(asc(Photo.file))
    return render_template("index.html", photos=photos)


@main.route("/uploads/<name>")
def display_file(name):
    return send_from_directory(current_app.config["UPLOAD_DIR"], name)


# Upload a new photo
@main.route("/upload/", methods=["GET", "POST"])
def newPhoto():
    if request.method == "POST":
        file = None
        if "fileToUpload" in request.files:
            file = request.files.get("fileToUpload")
        else:
            flash("Invalid request!", "error")

        if not file or not file.filename:
            flash("No file selected!", "error")
            return redirect(request.url)

        filepath = os.path.join(current_app.config["UPLOAD_DIR"], file.filename)
        file.save(filepath)

        newPhoto = Photo(
            name=request.form["user"],
            caption=request.form["caption"],
            description=request.form["description"],
            file=file.filename,
        )
        db.session.add(newPhoto)
        flash("New Photo %s Successfully Created" % newPhoto.name)
        db.session.commit()
        return redirect(url_for("main.homepage"))
    else:
        return render_template("upload.html")


# This is called when clicking on Edit. Goes to the edit page.
@main.route("/photo/<int:photo_id>/edit/", methods=["GET", "POST"])
def editPhoto(photo_id):
    editedPhoto = db.session.query(Photo).filter_by(id=photo_id).one()
    if request.method == "POST":
        if request.form["user"]:
            editedPhoto.name = request.form["user"]
            editedPhoto.caption = request.form["caption"]
            editedPhoto.description = request.form["description"]
            db.session.add(editedPhoto)
            db.session.commit()
            flash("Photo Successfully Edited %s" % editedPhoto.name)
            return redirect(url_for("main.homepage"))
    else:
        return render_template("edit.html", photo=editedPhoto)


# This is called when clicking on Delete.
@main.route("/photo/<int:photo_id>/delete/", methods=["GET", "POST"])
def deletePhoto(photo_id):
    fileResults = db.session.execute(
        text("select file from photo where id = " + str(photo_id))
    )
    filename = fileResults.first()[0]
    filepath = os.path.join(current_app.config["UPLOAD_DIR"], filename)
    os.unlink(filepath)
    db.session.execute(text("delete from photo where id = " + str(photo_id)))
    db.session.commit()

    flash("Photo id %s Successfully Deleted" % photo_id)
    return redirect(url_for("main.homepage"))
