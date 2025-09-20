from sqlalchemy import Column, Integer, String
from models.db import Base


class User(Base):
    # Define el nombre de la tabla en la base de datos a la que se mapea esta clase
    __tablename__ = "users"
    # Define la columna 'id' como un entero, clave primaria, indexada y de autoincremento
    id = Column(Integer, primary_key=True, index=True)
    # Define la columna 'username' como una cadena de hasta 50 caracteres
    # Asegura que cada nombre de usuario sea único, lo indexa para búsquedas rápidas y no permite valores nulos
    username = Column(String(50), unique=True, index=True, nullable=False)
    # Define la columna 'password' como una cadena de hasta 255 caracteres
    # No permite valores nulos. La longitud sugiere que se almacenará un hash de la contraseña, no la contraseña en texto plano
    password = Column(String(255), nullable=False)



