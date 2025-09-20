from models.db import Base
from config.database import engine
from flask import Flask
from config.jwt import *
from controllers.band_controller import band_bp
from controllers.users_controller import user_bp, register_jwt_error_handlers
from flask_jwt_extended import JWTManager



app = Flask(__name__)

# Configurar JWT
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = JWT_TOKEN_LOCATION
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = JWT_ACCESS_TOKEN_EXPIRES
app.config['JWT_HEADER_NAME'] = JWT_HEADER_NAME
app.config['JWT_HEADER_TYPE'] = JWT_HEADER_TYPE

jwt = JWTManager(app)

# Registrar el blueprint de bandas
app.register_blueprint(band_bp)
app.register_blueprint(user_bp)

# Registrar manejadores personalizados de error JWT
register_jwt_error_handlers(app)

if __name__ == "__main__":
    # Crear tablas automáticamente si no existen
    print("Verificando y creando tablas de base de datos si es necesario...")
    Base.metadata.create_all(engine)
    print("Tablas listas.")
    app.run(debug=True)
