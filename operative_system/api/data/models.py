from sqlalchemy import Column, Integer, String
from .database import Base

class Developer(Base):
    __tablename__ = 'developers'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    