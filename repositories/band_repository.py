from models.band_model import Band, Album
from sqlalchemy.orm import Session

class BandRepository:
    """
    Repositorio para la gestión de bandas musicales en la base de datos.
    Proporciona métodos para crear, consultar, actualizar y eliminar bandas,
    así como para interactuar con los álbumes asociados a cada banda.
    """

    def __init__(self, db_session: Session):
        self.db = db_session

    def get_all_bands(self):
        """
        Recupera todas las bandas musicales almacenadas en la base de datos.
        Utiliza una consulta ORM para obtener todas las instancias de la clase Band,
        permitiendo así listar todas las bandas registradas en el sistema. Es útil para
        mostrar catálogos, listados generales o para operaciones que requieran acceder
        a la colección completa de bandas.
        """
        return self.db.query(Band).all()

    def get_band_by_id(self, band_id: int):
        """
        Busca y retorna una banda específica según su identificador único (ID).
        Realiza una consulta filtrando por el campo 'id' de la tabla Band. Es útil
        para obtener detalles de una banda concreta, por ejemplo, al consultar su
        información o al realizar operaciones de actualización o eliminación.
        Devuelve la instancia de Band si existe, o None si no se encuentra.
        """
        return self.db.query(Band).filter(Band.id == band_id).first()

    def create_band(self, name: str):
        """
        Crea y almacena una nueva banda musical en la base de datos.
        Recibe el nombre de la banda como parámetro, instancia un nuevo objeto Band
        y lo agrega a la sesión de la base de datos. Tras confirmar la transacción,
        retorna la nueva banda creada, incluyendo su ID asignado automáticamente.
        Es útil para registrar nuevas bandas en el sistema.
        """
        new_band = Band(name=name)
        self.db.add(new_band)
        self.db.commit()
        self.db.refresh(new_band)
        return new_band

    def update_band(self, band_id: int, name: str = None):
        """
        Actualiza la información de una banda existente en la base de datos.
        Permite modificar el nombre de la banda identificada por su ID. Si la banda
        existe y se proporciona un nuevo nombre, se actualiza el registro y se guarda
        el cambio en la base de datos. Devuelve la instancia de la banda actualizada
        o None si no se encuentra la banda. Es útil para mantener actualizada la
        información de las bandas.
        """
        band = self.get_band_by_id(band_id)
        if band and name:
            band.name = name
            self.db.commit()
            self.db.refresh(band)
        return band

    def delete_band(self, band_id: int):
        """
        Elimina una banda musical de la base de datos según su identificador único (ID).
        Busca la banda correspondiente y, si existe, la elimina de la base de datos y
        confirma la transacción. Devuelve la instancia de la banda eliminada o None si
        no se encuentra. Es útil para operaciones administrativas o de mantenimiento
        donde se requiera remover bandas del sistema.
        """
        band = self.get_band_by_id(band_id)
        if band:
            self.db.delete(band)
            self.db.commit()
        return band
