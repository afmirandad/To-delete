from flask import Flask
from controllers.band_controller import band_bp

app = Flask(__name__)

# Registrar el blueprint de bandas
app.register_blueprint(band_bp)

if __name__ == "__main__":
    app.run(debug=True)
