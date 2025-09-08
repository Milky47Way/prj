from sqlalchemy.orm import Session
import models, schemas


# ----- Author -----

def get_author(db: Session, author_id: int):
    return db.query(models.Author).filter(models.Author.id == author_id).first()


def get_author_by_name(db: Session, name: str):
    return db.query(models.Author).filter(models.Author.name == name).first()


def get_authors(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Author).offset(skip).limit(limit).all()


def create_author(db: Session, author: schemas.AuthorCreate):
    db_author = models.Author(name=author.name)
    db.add(db_author)
    db.commit()
    db.refresh(db_author)
    return db_author


# ----- Book -----

def get_book(db: Session, book_id: int):
    return db.query(models.Book).filter(models.Book.id == book_id).first()


def get_books(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Book).offset(skip).limit(limit).all()


def create_book(db: Session, book: schemas.BookCreate):
    db_book = models.Book(name=book.name, author_id=book.author_id)
    db.add(db_book)
    db.commit()
    db.refresh(db_book)
    return db_book

# ----- User -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user(db: Session, login: str):
    return db.query(models.User).filter(models.User.login == login).first()


def authenticate_user(db: Session, login: str, password: str):
    user = get_user(db, login)
    if not user:
        return False
    # додаємо сіль перед перевіркою
    if not verify_password(password + user.salt, user.password):
        return False
    return user


def create_user(db: Session, login: str, password: str):
    salt = secrets.token_hex(16)
    hashed_password = get_password_hash(password + salt)

    db_user = models.User(
        login=login,
        password=hashed_password,  # тут зберігається саме hash
        salt=salt,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)