from sqlalchemy.orm import Session
from blog import models, schemas
from passlib.context import CryptContext
from datetime import timedelta , datetime 

from fastapi import Depends, FastAPI, HTTPException, status
from blog.database import SessionLocal

from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from settings import  SECRET_KEY, ALGORITHM


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def create_user(db: Session, user: schemas.User):
    _hashed_password = pwd_context.hash(user.hashed_password)
    db_user = models.User(email=user.email, hashed_password=_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def validate_user(db:Session, user:schemas.Login,form=None):
    _user = get_user_by_email(db, user.username) if form else get_user_by_email(db, user.email)
    if _user:
        if verify_password(user.password, _user.hashed_password):
            return _user
    return False


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data =schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

