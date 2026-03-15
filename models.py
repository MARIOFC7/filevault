from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contraseña = db.Column(db.String(200), nullable=False)
    cuota = db.Column(db.Integer, default=15000000)
    rol = db.Column(db.String(20), default='usuario')
    verificado = db.Column(db.Boolean, default=False)  # ✅ Nueva columna
    codigo_verificacion = db.Column(db.String(6), nullable=True)  # para MFA
