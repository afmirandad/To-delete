from services.users_services import UsersService
from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required

from config.database import get_db_session

service = UsersService(get_db_session())

user_bp = Blueprint('users', __name__)

@user_bp.route('/login', methods=['POST'])
def login():
    """
    POST /login
    Autentica a un usuario y retorna un token JWT si las credenciales son correctas.
    Parámetros esperados (JSON):
        username (str): Nombre de usuario.
        password (str): Contraseña del usuario.
    Respuesta: JSON con el token JWT o mensaje de error si las credenciales son inválidas.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'El nombre de usuario y la contraseña son obligatorios'}), 400
    user = service.authenticate_user(username, password)
    if user:
        access_token = create_access_token(identity={'id': user.id, 'username': user.username})
        return jsonify({'access_token': access_token}), 200
    return jsonify({'error': 'Credenciales inválidas'}), 401

@user_bp.route('/users', methods=['GET'])
def get_users():
    """
    GET /users
    Recupera y retorna todos los usuarios registrados en el sistema.
    Utiliza la capa de servicios para obtener la lista completa de usuarios.
    No recibe parámetros.
    Respuesta: JSON con la lista de usuarios.
    """
    users = service.get_all_users()
    return jsonify([{'id': u.id, 'username': u.username} for u in users]), 200

@user_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """
    GET /users/<user_id>
    Recupera la información de un usuario específico por su ID.
    Parámetros:
        user_id (int): ID del usuario a consultar (en la URL).
    Respuesta: JSON con los datos del usuario o 404 si no existe.
    """
    user = service.get_user_by_id(user_id)
    if user:
        return jsonify({'id': user.id, 'username': user.username}), 200
    return jsonify({'error': 'Usuario no encontrado'}), 404

@user_bp.route('/registry', methods=['POST'])
def create_user():
    """
    POST /registry
    Crea un nuevo usuario.
    Parámetros esperados (JSON):
        username (str): Nombre de usuario.
        password (str): Contraseña del usuario.
    Respuesta: JSON con los datos del usuario creado.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'El nombre de usuario y la contraseña son obligatorios'}), 400
    user = service.create_user(username, password)
    return jsonify({'id': user.id, 'username': user.username}), 201

@user_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """
    PUT /users/<user_id>
    Actualiza la información de un usuario existente.
    Parámetros:
        user_id (int): ID del usuario a actualizar (en la URL).
    Parámetros esperados (JSON):
        username (str, opcional): Nuevo nombre de usuario.
        password (str, opcional): Nueva contraseña del usuario.
    Respuesta: JSON con los datos del usuario actualizado o 404 si no existe.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = service.update_user(user_id, username, password)
    if user:
        return jsonify({'id': user.id, 'username': user.username}), 200
    return jsonify({'error': 'Usuario no encontrado'}), 404

@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """
    DELETE /users/<user_id>
    Elimina un usuario del sistema.
    Parámetros:
        user_id (int): ID del usuario a eliminar (en la URL).
    Respuesta: JSON confirmando la eliminación o 404 si no existe.
    """
    user = service.delete_user(user_id)
    if user:
        return jsonify({'message': 'Usuario eliminado correctamente'}), 200
    return jsonify({'error': 'Usuario no encontrado'}), 404