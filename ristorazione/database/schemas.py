from typing import List, Optional
from datetime import datetime

from pydantic import BaseModel


class User(BaseModel):
    uid: Optional[int]
    name: str
    surname: str
    email: str

    class Config:
        orm_mode = True


class UserList(BaseModel):
    users: List[User]


class UserCreatePlain(User):
    password: str

    class Config:
        orm_mode = True


class UserCreate(User):
    hash: bytes

    class Config:
        orm_mode = True