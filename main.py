from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session
from blog import utils, models, schemas
from blog.database import SessionLocal, engine
from datetime import timedelta, datetime
from settings import  SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt


models.Base.metadata.create_all(bind=engine)
app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/token", response_model=schemas.Token)
def login_for_access_token(db: Session = Depends(get_db),form_data: OAuth2PasswordRequestForm = Depends()):
    user = utils.validate_user(db, user=form_data,form=True)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": user.email, "exp": access_token_expires}
    access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users/", response_model=schemas.ResUser)
def create_user(user: schemas.User, db: Session = Depends(get_db)):
    db_user = utils.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return utils.create_user(db=db, user=user)

@app.post("/login/", response_model=schemas.ResUser)
def user_login(user:schemas.Login,db:Session=Depends(get_db)):
    verify_user = utils.validate_user(db, user=user)
    if not verify_user:
        raise HTTPException(status_code=400, detail="Login Failed")
    return user

@app.get("/users/me/", response_model=schemas.ResUser)
def read_users_me(current_user:schemas.User = Depends(utils.get_current_user)):
    return current_user
