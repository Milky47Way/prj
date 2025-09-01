from pydantic import BaseModel
from typing import List, Optional


# ----- Book Schemas -----

class BookBase(BaseModel):
    name: str


class BookCreate(BookBase):
    author_id: int


class Book(BookBase):
    id: int
    author_id: int

    class Config:
        orm_mode = True   # дозволяє повертати дані з SQLAlchemy-моделей


# ----- Author Schemas -----

class AuthorBase(BaseModel):
    name: str


class AuthorCreate(AuthorBase):
    pass


class Author(AuthorBase):
    id: int
    books: List[Book] = []   # Автор може мати список книжок

    class Config:
        orm_mode = True