from repositories.band_repository import BandRepository
from models.band_model import Band
from sqlalchemy.orm import Session

"""
Librerías utilizadas:
- repositories.band_repository: Proporciona la clase BandRepository para la gestión de bandas en la base de datos.
- models.band_model: Define el modelo Band que representa la entidad de banda musical.
- sqlalchemy.orm.Session: Permite manejar la sesión de la base de datos para realizar operaciones transaccionales.
"""

class BandService:
    """
    Capa de servicios para la gestión de bandas musicales.
    Esta clase orquesta la lógica de negocio relacionada con las bandas, utilizando el repositorio para acceder a los datos.
    Permite mantener la lógica de negocio separada de la capa de acceso a datos y de la base de datos.
    """
    def __init__(self, db_session: Session):
        """
        Inicializa el servicio de bandas con una sesión de base de datos y un repositorio de bandas.
        """
        self.repository = BandRepository(db_session)

    def listar_bandas(self):
        """
        Recupera y retorna todas las bandas musicales registradas en el sistema.
        Utiliza el repositorio para obtener la lista completa de bandas.
        Es útil para mostrar catálogos o listados generales de bandas.
        """
        return self.repository.get_all_bands()

    def obtener_banda(self, band_id: int):
        """
        Busca y retorna una banda específica por su identificador único (ID).
        Utiliza el repositorio para acceder a la banda correspondiente.
        Es útil para mostrar detalles o realizar operaciones sobre una banda concreta.
        """
        return self.repository.get_band_by_id(band_id)

    def crear_banda(self, name: str):
        """
        Crea una nueva banda musical con el nombre proporcionado.
        Utiliza el repositorio para almacenar la nueva banda en la base de datos.
        Es útil para registrar nuevas bandas en el sistema.
        """
        return self.repository.create_band(name)

    def actualizar_banda(self, band_id: int, name: str = None):
        """
        Actualiza la información de una banda existente, permitiendo modificar su nombre.
        Utiliza el repositorio para realizar la actualización en la base de datos.
        Es útil para mantener actualizada la información de las bandas.
        """
        return self.repository.update_band(band_id, name)

    def eliminar_banda(self, band_id: int):
        """
        Elimina una banda musical del sistema según su identificador único (ID).
        Utiliza el repositorio para eliminar la banda de la base de datos.
        Es útil para operaciones administrativas o de mantenimiento.
        """
        return self.repository.delete_band(band_id)
