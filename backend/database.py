import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.models import Base

DATABASE_URL = os.getenv('THREATLENS_DB_URL', 'sqlite:///./threatlens.db')

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)