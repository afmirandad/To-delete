from flask import Flask
from controllers.band_controller import band_bp
from controllers.users_controller import user_bp

app = Flask(__name__)

# Registrar el blueprint de bandas
app.register_blueprint(band_bp)
app.register_blueprint(user_bp)

if __name__ == "__main__":
    app.run(debug=True)
