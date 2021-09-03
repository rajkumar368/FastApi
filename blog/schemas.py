from typing import Optional
from pydantic import BaseModel

class User(BaseModel):
    email:str
    hashed_password:str
    is_active:Optional[bool]=True

    class Config:
        orm_mode = True

class ResUser(BaseModel):
    email:str
    is_active:Optional[bool]=True

    class Config:
        orm_mode = True

class Login(BaseModel):
    email:str
    password:str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
