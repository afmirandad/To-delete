
# Importaciones de librerías:
# - sqlalchemy: Proporciona herramientas para trabajar con bases de datos relacionales en Python mediante ORM (Object Relational Mapping).
#   - Column, Integer, String, ForeignKey: Permiten definir los tipos de columnas y relaciones entre tablas en los modelos de base de datos.
# - sqlalchemy.orm: Incluye utilidades para la gestión de relaciones y la declaración de modelos.
#   - relationship: Permite definir relaciones entre tablas (por ejemplo, uno a muchos).
#   - declarative_base: Se utiliza para crear una clase base a partir de la cual se definen los modelos ORM.

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()

"""
La clase Band representa una banda musical dentro del sistema. Cada instancia de esta clase corresponde a una banda específica, 
almacenando información relevante como su nombre y la relación con sus álbumes. Esta clase está mapeada a la tabla 'bands' en 
la base de datos y permite gestionar la información de las bandas, así como acceder a todos los álbumes asociados a cada banda 
mediante una relación uno a muchos.
"""
class Band(Base):
    __tablename__ = 'bands'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    albums = relationship('Album', back_populates='band', cascade='all, delete-orphan')

"""
La clase Album representa un álbum musical que pertenece a una banda. Cada instancia de esta clase corresponde a un álbum específico, 
almacenando información como el título y la referencia a la banda a la que pertenece. Esta clase está mapeada a la tabla 'albums' en 
la base de datos y permite gestionar los álbumes, así como establecer la relación de pertenencia con una banda mediante una clave foránea.
"""
class Album(Base):
    __tablename__ = 'albums'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    band_id = Column(Integer, ForeignKey('bands.id'))
    band = relationship('Band', back_populates='albums')