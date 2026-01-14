from flask import Flask, request, render_template, send_from_directory, url_for, redirect, flash
import os, uuid, time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from datetime import datetime

# -------------------- DATABASE --------------------
import os

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)

db = client["expyra_db"]

users_col = db["users"]
files_col = db["files"]
audit_col = db["audit_logs"]

print("MongoDB connected:", db.list_collection_names())

# -------------------- APP CONFIG --------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB

# -------------------- LOGIN MANAGER --------------------
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------- USER MODEL --------------------
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    user = users_col.find_one({"username": username})
    return User(username) if user else None

# -------------------- HELPERS --------------------
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def format_time(seconds):
    if seconds <= 0:
        return "Expired"
    elif seconds < 3600:
        return f"{seconds // 60} min"
    elif seconds < 86400:
        return f"{seconds // 3600} hr"
    return f"{seconds // 86400} days"

def log_action(action, file_name, file_id=None):
    audit_col.insert_one({
        "action": action,
        "file_name": file_name,
        "file_id": file_id,
        "user": current_user.id if current_user.is_authenticated else "Guest",
        "ip": request.remote_addr,
        "timestamp": datetime.utcnow()
    })

# -------------------- ROUTES --------------------
@app.route("/")
def welcome():
    return render_template("welcome.html")

@app.route("/home")
@login_required
def home():
    return render_template("home.html")

# -------------------- AUTH --------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        if users_col.find_one({"username": request.form["username"]}):
            flash("Username already exists!", "danger")
            return redirect(url_for("signup"))

        users_col.insert_one({
            "username": request.form["username"],
            "password": generate_password_hash(request.form["password"]),
            "email": request.form["email"].strip().lower()
        })

        flash("Signup successful!", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = users_col.find_one({
            "$or": [
                {"username": request.form["username"]},
                {"email": request.form["username"]}
            ]
        })

        if user and check_password_hash(user["password"], request.form["password"]):
            login_user(User(user["username"]))
            return redirect(url_for("home"))

        flash("Invalid credentials!", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# -------------------- DASHBOARD --------------------
@app.route("/dashboard")
@login_required
def dashboard():
    now = time.time()
    files = []

    for f in files_col.find({"owner": current_user.id}):
        status = "Revoked" if f.get("revoked") else ("Expired" if now > f["expiry"] else "Active")

        files.append({
            "file_id": f["file_id"],
            "filename": f["filename"].split("_", 1)[1],
            "expiry_readable": format_time(int(f["expiry"] - now)),
            "status": status,
            "downloads": f.get("downloads", 0),
            "protected": "Yes" if f.get("password") else "No",
            "link": url_for("download_file", file_id=f["file_id"], _external=True),
            "last_downloaded": f.get("last_downloaded")
        })

    return render_template("dashboard.html", files=files)

# -------------------- AUDIT LOGS --------------------
@app.route("/audit-logs")
@login_required
def audit_logs():
    logs = audit_col.find().sort("timestamp", -1)
    return render_template("audit_logs.html", logs=logs)

# -------------------- UPLOAD --------------------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_page():
    if request.method == "POST":
        file = request.files.get("file")
        if not file or not allowed_file(file.filename):
            return "Invalid file"

        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        path = os.path.join(UPLOAD_FOLDER, f"{file_id}_{filename}")
        file.save(path)

        expiry_seconds = int(request.form.get("expiry", 60))
        password = request.form.get("password")

        files_col.insert_one({
            "owner": current_user.id,
            "file_id": file_id,
            "filename": f"{file_id}_{filename}",
            "expiry": time.time() + expiry_seconds,
            "downloads": 0,
            "password": generate_password_hash(password) if password else None,
            "revoked": False,
            "last_downloaded": None
        })

        log_action("UPLOAD", filename, file_id)

        return render_template(
            "link.html",
            url=url_for("download_file", file_id=file_id, _external=True),
            expiry=format_time(expiry_seconds),
            protected=True if password else False
        )

    return render_template("index.html")

# -------------------- DOWNLOAD --------------------
@app.route("/download/<file_id>", methods=["GET", "POST"])
def download_file(file_id):
    file = files_col.find_one({"file_id": file_id})
    if not file:
        return render_template("notfound.html")

    if file.get("revoked"):
        return render_template("expired.html", message="Access revoked")

    if time.time() > file["expiry"]:
        return render_template("expired.html")

    if file["password"]:
        if request.method == "POST" and check_password_hash(file["password"], request.form["password"]):
            pass
        else:
            return render_template("password.html")

    files_col.update_one(
        {"_id": file["_id"]},
        {"$inc": {"downloads": 1}, "$set": {"last_downloaded": datetime.utcnow()}}
    )

    log_action("DOWNLOAD", file["filename"], file_id)

    audit_col.insert_one({
    "action": "DOWNLOAD",
    "filename": file["filename"],   # stored with uuid_prefix
    "downloaded_by": current_user.id if current_user.is_authenticated else "Guest",
    "ip_address": request.remote_addr,
    "timestamp": datetime.utcnow()
})


    return send_from_directory(UPLOAD_FOLDER, file["filename"], as_attachment=True)

# -------------------- DELETE --------------------
@app.route("/delete/<file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    file = files_col.find_one({"file_id": file_id, "owner": current_user.id})
    if file:
        log_action("DELETE", file["filename"], file_id)
        files_col.delete_one({"_id": file["_id"]})

    return redirect(url_for("dashboard"))

# -------------------- TOGGLE ACCESS --------------------
@app.route("/toggle-access/<file_id>", methods=["POST"])
@login_required
def toggle_access(file_id):
    file = files_col.find_one({"file_id": file_id, "owner": current_user.id})
    if file:
        new_status = not file.get("revoked", False)
        files_col.update_one({"_id": file["_id"]}, {"$set": {"revoked": new_status}})
        log_action("REVOKE" if new_status else "ENABLE", file["filename"], file_id)

    return redirect(url_for("dashboard"))

# -------------------- MAIN --------------------
if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
