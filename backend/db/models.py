from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from db.database import Base
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    is_verified = Column(Boolean, default=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)
