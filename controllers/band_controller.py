import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from flask import Blueprint, request, jsonify
from services.band_service import BandService
from flask_jwt_extended import jwt_required
band_bp =Blueprint('band_bp',__name__)

# Importar la sesión de la base de datos desde config/database.py
from config.database import get_db_session

# Instancia global de servicio (en producción usar contexto de app o request)
service = BandService(get_db_session())

band_bp =Blueprint('band_bp',__name__)


@band_bp.route('/bands', methods=['GET'])
@jwt_required()
def get_bands():
	"""
	GET /bands
	Recupera y retorna todas las bandas musicales registradas en el sistema.
	Utiliza la capa de servicios para obtener la lista completa de bandas.
	No recibe parámetros.
	Respuesta: JSON con la lista de bandas.
	"""
	logger.info("Consulta de todas las bandas")
	bands = service.listar_bandas()
	return jsonify([{'id': b.id, 'name': b.name} for b in bands]), 200, {'Content-Type': 'application/json; charset=utf-8'}



@band_bp.route('/bands/<int:band_id>', methods=['GET'])
def get_band(band_id):
	"""
	GET /bands/<band_id>
	Recupera la información de una banda específica por su ID.
	Parámetros:
		band_id (int): ID de la banda a consultar (en la URL).
	Respuesta: JSON con los datos de la banda o 404 si no existe.
	"""
	band = service.obtener_banda(band_id)
	if band:
		logger.info(f"Consulta de banda por ID: {band_id}")
		return jsonify({'id': band.id, 'name': band.name}), 200, {'Content-Type': 'application/json; charset=utf-8'}
	logger.warning(f"Banda no encontrada: {band_id}")
	return jsonify({'error': 'Banda no encontrada'}), 404, {'Content-Type': 'application/json; charset=utf-8'}



@band_bp.route('/bands', methods=['POST'])
def create_band():
	"""
	POST /bands
	Crea una nueva banda musical.
	Parámetros esperados (JSON):
		name (str): Nombre de la banda.
	Respuesta: JSON con los datos de la banda creada.
	"""
	data = request.get_json()
	name = data.get('name')
	if not name:
		logger.warning("Intento de crear banda sin nombre")
		return jsonify({'error': 'El nombre es obligatorio'}), 400, {'Content-Type': 'application/json; charset=utf-8'}
	band = service.crear_banda(name)
	logger.info(f"Banda creada: {name}")
	return jsonify({'id': band.id, 'name': band.name}), 201, {'Content-Type': 'application/json; charset=utf-8'}



@band_bp.route('/bands/<int:band_id>', methods=['PUT'])
def update_band(band_id):
	"""
	PUT /bands/<band_id>
	Actualiza la información de una banda existente.
	Parámetros:
		band_id (int): ID de la banda a actualizar (en la URL).
		name (str): Nuevo nombre de la banda (en el cuerpo JSON).
	Respuesta: JSON con los datos de la banda actualizada o error si no existe.
	"""
	data = request.get_json()
	name = data.get('name')
	band = service.actualizar_banda(band_id, name)
	if band:
		logger.info(f"Banda actualizada: {band_id}")
		return jsonify({'id': band.id, 'name': band.name}), 200, {'Content-Type': 'application/json; charset=utf-8'}
	logger.warning(f"Banda no encontrada para actualizar: {band_id}")
	return jsonify({'error': 'Banda no encontrada'}), 404, {'Content-Type': 'application/json; charset=utf-8'}



@band_bp.route('/bands/<int:band_id>', methods=['DELETE'])
def delete_band(band_id):
	"""
	DELETE /bands/<band_id>
	Elimina una banda específica por su ID.
	Parámetros:
		band_id (int): ID de la banda a eliminar (en la URL).
	Respuesta: JSON con mensaje de éxito o error si no existe.
	"""
	band = service.eliminar_banda(band_id)
	if band:
		logger.info(f"Banda eliminada: {band_id}")
		return jsonify({'message': 'Banda eliminada'}), 200, {'Content-Type': 'application/json; charset=utf-8'}
	logger.warning(f"Banda no encontrada para eliminar: {band_id}")
	return jsonify({'error': 'Banda no encontrada'}), 404, {'Content-Type': 'application/json; charset=utf-8'}
