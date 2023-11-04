from typing import Optional

from email_validator import validate_email, EmailNotValidError
from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Boolean, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from smtplib import SMTP
import secrets

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.templating import Jinja2Templates

SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://root:root@localhost/login_register"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
templates = Jinja2Templates(directory="templates")  # assumes a templates directory


class UserDBModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    fullname = Column(String(255), index=True)
    email = Column(String(255), unique=True, index=True)
    password_hashed = Column(String(255))
    disabled = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)

app = FastAPI()

SECRET_KEY = "YOUR_SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str
    message: str


class User(BaseModel):
    username: str
    email: str
    fullname: str
    password: str
    disabled: Optional[bool] = False


class UserInDB(User):
    hashed_password: str


class TokenData(BaseModel):
    username: Optional[str] = None


class ForgetPassword(BaseModel):
    email: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

forgot_password_token: str = secrets.token_urlsafe(30)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user(db: Session, email: str):
    return db.query(UserDBModel).filter(UserDBModel.email == email).first()


def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.password_hashed):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.get("/")
def root():
    headers = {"ngrok-skip-browser-warning": "1"}
    content = {"message": "Hello, World!"}@app.get("/reset", response_class=HTMLResponse)


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if user is None or not user.email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "message": f"Welcome {form_data.username}"}

@app.post("/register")
def register_user(user: User, db: Session = Depends(get_db)):
    db_user = get_user(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # validating email
    try:
        validate_email(user.email)
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))

    hashed_password = get_password_hash(user.password)
    db.add(
        UserDBModel(username=user.username, email=user.email, fullname=user.fullname, password_hashed=hashed_password))
    db.commit()
    return {"username": user.username, "email": user.email, "fullname": user.fullname,
            "message": "Successfully registered"}


@app.post("/forget_password")
def forget_password(user_email: ForgetPassword, db: Session = Depends(get_db)):
    user = get_user(db, user_email.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate a reset password code
    reset_password_code = secrets.token_urlsafe(20)

    # This is the email subject
    email_subject = "Reset Your Password"

    # This is the email content
    email_content = f"""
    Hi {user.username}!
    Click the link below to reset your password.
    http://127.0.0.1:8000/reset?token={reset_password_code}
    If you didn't request a password reset, just ignore this email.
    """

    # Merge subject and content into one message
    msg = "Subject: {}\n\n{}".format(email_subject, email_content)

    # Now, you would send the email
    with SMTP("smtp.mailgun.org") as smtp:  # Specify your SMTP settings
        smtp.login("postmaster@sandbox1e844abd04cf40daafd02d812e2b299c.mailgun.org",
                   "5e18985928b90982fa2a2cecae25c87b-3e508ae1-6e87e9be")  # Specify your credential here
        smtp.sendmail('postmaster@sandbox1e844abd04cf40daafd02d812e2b299c.mailgun.org', user.email, msg)

    # For this example, you will return the token
    return {"message": "An email has been sent to reset your password."}

@app.get("/reset", response_class=HTMLResponse)
def reset_password(request: Request, token: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
