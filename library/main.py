from fastapi import FastAPI, HTTPException, Query, Depends #⬅️⬅️
from sqlalchemy.orm import Session #⬅️⬅️
from pydantic import BaseModel, Field

import models, schemas, crud #⬅️⬅️
from database import engine, Base, SessionLocal #⬅️⬅️

# Створюємо таблиці у базі
Base.metadata.create_all(bind=engine) #⬅️⬅️

app = FastAPI()

# Dependency для отримання сесії БД
def get_db(): #⬅️⬅️
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Пустий словник для збереження даних
# library = {} #⬅️⬅️

# Модель для книги з використанням Annotated та валідації
# class Book(BaseModel): #⬅️⬅️
#     title: str = Field(...,
#                        title="Назва книги",
#                        description="Назва книги повинна бути вказана",
#                        min_length=1)
#     author: str = Field(...,
#                         title="Автор",
#                         description="Ім'я автора",
#                         min_length=3,
#                         max_length=50)
#     pages: int = Field(...,
#                        title="Кількість сторінок",
#                        description="Кількість сторінок повинна бути більше 10",
#                        gt=10)

# Створення нової книги
# ----- Автори ----- #⬅️⬅️ #⬅️⬅️ #⬅️⬅️

@app.post("/authors/", response_model=schemas.Author)
def create_author(author: schemas.AuthorCreate, db: Session = Depends(get_db)):
    db_author = crud.get_author_by_name(db, name=author.name)
    if db_author:
        raise HTTPException(status_code=409, detail="Автор вже існує")
    return crud.create_author(db=db, author=author)


@app.get("/authors/", response_model=list[schemas.Author])
def get_authors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_authors(db, skip=skip, limit=limit)


@app.get("/authors/{author_id}", response_model=schemas.Author)
def get_author(author_id: int, db: Session = Depends(get_db)):
    db_author = crud.get_author(db, author_id=author_id)
    if not db_author:
        raise HTTPException(status_code=404, detail="Автор не знайдений")
    return db_author


# ----- Книги -----

@app.post("/books/", response_model=schemas.Book)
def create_book(book: schemas.BookCreate, db: Session = Depends(get_db)):
    # перевірка на існування автора
    db_author = crud.get_author(db, author_id=book.author_id)
    if not db_author:
        raise HTTPException(status_code=404, detail="Автор не знайдений")

    # перевірка на дубль книги
    db_books = crud.get_books(db)
    for b in db_books:
        if b.name.lower() == book.name.lower() and b.author_id == book.author_id:
            raise HTTPException(status_code=409, detail="Книга вже існує у цього автора")

    return crud.create_book(db=db, book=book)


@app.get("/books/", response_model=list[schemas.Book])
def get_books(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_books(db, skip=skip, limit=limit)


@app.get("/books/{book_id}", response_model=schemas.Book)
def get_book(book_id: int, db: Session = Depends(get_db)):
    db_book = crud.get_book(db, book_id=book_id)
    if not db_book:
        raise HTTPException(status_code=404, detail="Книга не знайдена")
    return db_book

# pip install "uvicorn[standard]"
# uvicorn main:app --reload
# main - назва вашого файлу