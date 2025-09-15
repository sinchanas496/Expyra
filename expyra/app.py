from flask import Flask, request, render_template, send_from_directory, url_for, redirect, flash
import os, uuid, time
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from datetime import datetime

# -------------------- DATABASE --------------------
MONGO_URI = "mongodb+srv://expyra_user:%40Sinchana14@cluster0.fx8izpc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["expyra_db"]     # database name
users_col = db["users"]      # collection for users
files_col = db["files"]      # collection for uploaded files

print("MongoDB connected:", db.list_collection_names())

# -------------------- APP CONFIG --------------------
app = Flask(__name__)
app.secret_key = "supersecretkey"  # required for sessions

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024   # ✅ 5 MB file size limit

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
    if user:
        return User(username)
    return None

# -------------------- HELPERS --------------------
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_time(seconds):
    if seconds <= 0:
        return "Expired"
    elif seconds < 3600:
        return f"{seconds // 60} min"
    elif seconds < 86400:
        return f"{seconds // 3600} hr"
    else:
        return f"{seconds // 86400} days"

# -------------------- ROUTES --------------------
@app.route('/')
def home():
    return render_template('home.html')

# ✅ Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        if users_col.find_one({"username": username}):
            flash("User already exists!", "danger")
            return redirect(url_for("signup"))

        hashed_pw = generate_password_hash(password)
        users_col.insert_one({"username": username, "password": hashed_pw})
        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

# ✅ Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = users_col.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            login_user(User(username))
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

# ✅ Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

@app.route('/dashboard')
@login_required
def dashboard():
    now = time.time()
    user_files = files_col.find({"owner": current_user.id})

    files_list = []
    for file in user_files:
        status = "Expired" if now > file["expiry"] else "Active"
        files_list.append({
            "id": str(file["_id"]),
            "file_id": file["file_id"],
            "filename": file["filename"].split("_", 1)[1],
            "expiry_readable": format_time(int(file["expiry"] - now)),
            "status": status,
            "downloads": file.get("downloads", 0),
            "protected": "Yes" if file.get("password") else "No",
            "link": url_for("download_file", file_id=file["file_id"], _external=True),
            "last_downloaded": file.get("last_downloaded")
        })
    return render_template("dashboard.html", files=files_list)


# ✅ Upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_page():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No file part"
        file = request.files['file']
        if file.filename == '':
            return "No selected file"
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_id = str(uuid.uuid4())
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_id + "_" + filename)
            file.save(filepath)

            expiry_seconds = int(request.form.get("expiry", "60"))
            expiry_time = time.time() + expiry_seconds

            password = request.form.get("password")
            password_hash = generate_password_hash(password) if password else None

            files_col.insert_one({
                "owner": current_user.id,
                "file_id": file_id,
                "filename": file_id + "_" + filename,
                "expiry": expiry_time,
                "downloads": 0,
                "password": password_hash,
                "last_downloaded": None   # ✅ new field
            })

            download_url = url_for('download_file', file_id=file_id, _external=True)
            return render_template("link.html",
                                   url=download_url,
                                   expiry=format_time(expiry_seconds),
                                   protected=True if password else False)
        return "File type not allowed"

    return render_template("index.html")

# ✅ Download Page
@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'POST':
        file_input = request.form.get("file_id")
        if "/" in file_input:
            file_id = file_input.strip().split("/")[-1]
        else:
            file_id = file_input.strip()
        return redirect(url_for('download_file', file_id=file_id))

    return render_template('download.html')

# ✅ File Download
@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    file_info = files_col.find_one({"file_id": file_id})
    if not file_info:
        return render_template("notfound.html")

    if time.time() > file_info["expiry"]:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_info["filename"]))
        except:
            pass
        files_col.delete_one({"_id": file_info["_id"]})
        return render_template("expired.html")

    if file_info["password"]:
        if request.method == 'POST':
            entered_password = request.form['password']
            if check_password_hash(file_info["password"], entered_password):
                files_col.update_one(
                    {"_id": file_info["_id"]},
                    {"$inc": {"downloads": 1}, "$set": {"last_downloaded": datetime.utcnow()}}
                )
                return send_from_directory(app.config['UPLOAD_FOLDER'],
                                           file_info["filename"],
                                           as_attachment=True)
            else:
                return render_template("password.html", error="Incorrect password")
        return render_template("password.html")

    # no password
    files_col.update_one(
        {"_id": file_info["_id"]},
        {"$inc": {"downloads": 1}, "$set": {"last_downloaded": datetime.utcnow()}}
    )
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_info["filename"], as_attachment=True)
# ✅ Delete File
@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_info = files_col.find_one({"file_id": file_id, "owner": current_user.id})
    if not file_info:
        flash("File not found or not authorized!", "danger")
        return redirect(url_for("dashboard"))

    # remove file from local uploads folder
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_info["filename"]))
    except:
        pass

    # remove from MongoDB
    files_col.delete_one({"_id": file_info["_id"]})
    flash("File deleted successfully!", "success")
    return redirect(url_for("dashboard"))

# -------------------- ERROR HANDLER --------------------
@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File too large! Max size is 5 MB.", "danger")
    return redirect(url_for("upload_page"))

# -------------------- MAIN --------------------
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
