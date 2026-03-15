from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
from datetime import datetime
import os, random

# Configuración
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Configuración de correo (usa contraseña de aplicación de Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
mail = Mail(app)

db = SQLAlchemy(app)

# Google OAuth
google_bp = make_google_blueprint(
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# Modelos
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    cuota = db.Column(db.Integer, default=15000000)  # 15 MB por defecto
    rol = db.Column(db.String(20), default='usuario')
    verificado = db.Column(db.Boolean, default=False)
    archivos = db.relationship('Archivo', backref='usuario', lazy=True)

class Archivo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    tamano = db.Column(db.Integer, nullable=False)
    fecha_subida = db.Column(db.DateTime, default=datetime.utcnow)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

# Funciones auxiliares
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Rutas
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/crear_password', methods=['GET', 'POST'])
def crear_password():
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']
        if password == confirm:
            hashed_password = generate_password_hash(password)
            usuario = Usuario.query.filter_by(email=session['user_email']).first()
            usuario.password = hashed_password

            # Generar código de verificación
            codigo = random.randint(100000, 999999)
            session['codigo_verificacion'] = codigo

            msg = Message("Código de verificación",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[usuario.email])
            msg.body = f"Tu código de verificación es: {codigo}"
            mail.send(msg)

            db.session.commit()
            flash("Contraseña creada. Se envió un código de verificación a tu correo.", "info")
            return redirect(url_for('verificar_codigo'))
        else:
            flash("Las contraseñas no coinciden", "error")
    return render_template('crear_password.html')


@app.route('/verificar', methods=['GET', 'POST'])
def verificar_codigo():
    if request.method == 'POST':
        codigo_ingresado = request.form['codigo']
        if str(session.get('codigo_verificacion')) == codigo_ingresado:
            usuario = Usuario.query.filter_by(email=session['user_email']).first()
            if usuario:
                usuario.verificado = True
                db.session.commit()
            flash("Cuenta verificada correctamente", "success")
            return redirect(url_for('home'))
        else:
            flash("Código incorrecto", "danger")
    return render_template('verificar.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    usuario = Usuario.query.filter_by(email=email).first()
    if usuario and check_password_hash(usuario.password, password):
        if not usuario.verificado:
            flash("Debes verificar tu cuenta antes de ingresar.", "warning")
            return redirect(url_for('verificar_codigo'))
        session['user_id'] = usuario.id
        session['rol'] = usuario.rol
        flash("Login exitoso", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Credenciales inválidas", "error")
        return redirect(url_for('home'))

@app.route("/login/google")
def login_google():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    info = resp.json()
    email = info["email"]
    nombre = info["name"]

    usuario = Usuario.query.filter_by(email=email).first()
    if not usuario:
        usuario = Usuario(nombre=nombre, email=email, password="", verificado=False)
        db.session.add(usuario)
        db.session.commit()

    session['user_email'] = email
    return redirect(url_for("crear_password"))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    usuario = db.session.get(Usuario, session['user_id'])
    archivos = usuario.archivos
    return render_template('dashboard.html', archivos=archivos)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No se seleccionó ningún archivo')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('Nombre de archivo vacío')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_size = len(file.read())
            file.seek(0)

            usuario = db.session.get(Usuario, session['user_id'])
            uso_actual = sum([a.tamano for a in usuario.archivos])

            if uso_actual + file_size > usuario.cuota:
                flash('Has superado tu cuota de almacenamiento.')
                return redirect(request.url)

            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(usuario.id))
            os.makedirs(user_folder, exist_ok=True)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            nuevo_archivo = Archivo(nombre=filename, tamano=file_size, usuario_id=usuario.id)
            db.session.add(nuevo_archivo)
            db.session.commit()

            flash('Archivo subido exitosamente.')
            return redirect(url_for('dashboard'))

    return render_template('upload.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('rol') != 'admin':
        flash('Acceso no autorizado.')
        return redirect(url_for('home'))

    usuarios = Usuario.query.all()
    datos = []
    for u in usuarios:
        usado = sum([a.tamano for a in u.archivos])
        datos.append({'nombre': u.nombre, 'email': u.email, 'cuota': u.cuota, 'usado': usado})
    return render_template('admin_dashboard.html', usuarios=datos)

@app.route('/reenviar_codigo')
def reenviar_codigo():
    if 'user_email' not in session:
        flash("No hay usuario en sesión para reenviar código.", "error")
        return redirect(url_for('home'))

    # Generar nuevo código
    codigo = random.randint(100000, 999999)
    session['codigo_verificacion'] = codigo

    # Enviar correo
    msg = Message("Nuevo código de verificación",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[session['user_email']])
    msg.body = f"Tu nuevo código de verificación es: {codigo}"
    mail.send(msg)

    flash("Se envió un nuevo código de verificación a tu correo.", "info")
    return redirect(url_for('verificar_codigo'))



@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada", "info")
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

