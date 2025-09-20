from repositories.users_repository import UsersRepository
from models.users_model import User
from werkzeug.security import generate_password_hash, check_password_hash

class UsersService:
    def __init__(self, db_session):
        self.users_repository = UsersRepository(db_session)

    def authenticate_user(self, username: str, password: str):
        user = self.users_repository.db.query(User).filter(User.username == username).first()
        if user and check_password_hash(user.password, password):
            return user
        return None

    def get_all_users(self):
        return self.users_repository.get_all_users()

    def get_user_by_id(self, user_id: int):
        return self.users_repository.get_user_by_id(user_id)

    def create_user(self, username: str, password: str):
        password_hashed = generate_password_hash(password)
        return self.users_repository.create_user(username, password_hashed)

    def update_user(self, user_id: int, username: str = None, password: str = None):
        return self.users_repository.update_user(user_id, username, password)

    def delete_user(self, user_id: int):
        return self.users_repository.delete_user(user_id)