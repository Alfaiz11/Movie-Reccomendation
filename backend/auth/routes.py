from fastapi import APIRouter, HTTPException, Depends, Request, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi import UploadFile, File 
import pandas as pd
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from typing import Literal
import os
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from utils.tokens import generate_verification_token
from utils.tokens import confirm_token
from utils.email_utils import send_verification_email
from db.models import User
from db.database import engine,get_db

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_router = APIRouter()
templates = Jinja2Templates(directory="backend/templates")
print(engine.url)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    role: Literal["admin", "student"]

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_role: str):
    def role_checker(request: Request):
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(status_code=401, detail="Missing token in cookies")

        payload = decode_token(token)  # Your decode_token logic
        if payload.get("role") != required_role:
            raise HTTPException(status_code=403, detail="Not authorized")
        return payload  # Contains user_id, role, etc.

    return role_checker

# === JSON API SIGNUP ===
@auth_router.post("/signup")
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    print(f"Creating user with email: {payload.email}")
    return {"msg": "User created successfully"}

# === HTMX SIGNUP FORM ===
@auth_router.get("/signup-page", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@auth_router.post("/signup-form", response_class=HTMLResponse)
def signup_form(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return HTMLResponse(content="❌ User already exists", status_code=400)
    
    new_user = User(email=email, hashed_password=hash_password(password), role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    print("✅ User added:", new_user.email)
    token = generate_verification_token(email)
    link = f"{os.getenv('FRONTEND_URL', 'http://127.0.0.1:8000')}/auth/verify-email?token={token}"
    send_verification_email(email, link)
    return HTMLResponse(content="✅ User created successfully!")

# === JSON API LOGIN ===
@auth_router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
@auth_router.get("/login")
def redirect_to_login_page(msg: str = ""):
    return RedirectResponse(url=f"/auth/login-page?msg={msg}", status_code=302)


# === HTMX LOGIN FORM ===
@auth_router.get("/login-page", response_class=HTMLResponse)
def login_page(request: Request):
    logged_out = request.cookies.get("logged_out")

    response = templates.TemplateResponse("login.html", {
        "request": request,
        "logged_out": logged_out
    })

    # 🍪 Clear the cookie after reading so it doesn’t show again next time
    response.delete_cookie("logged_out")

    return response


@auth_router.post("/login-form", response_class=HTMLResponse)
def login_form(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return HTMLResponse(
            content='<div class="toast error" style="text-align:center;">❌ Invalid email or password</div>',
            status_code=200
        )

    # Redirect logic
    if user.role == "admin":
        redirect_url = "/auth/admin/dashboard"
    elif user.role == "student":
        redirect_url = "/auth/student/courses"
    elif user.role == "teacher":
        redirect_url = "/auth/teacher/dashboard"
    else:
        return HTMLResponse(content="Invalid role", status_code=400)

    # ⛓️ Create JWT token
    access_token = create_access_token(data={
        "sub": user.email,
        "role": user.role,
        "user_id": user.id
    }, expires_delta=timedelta(hours=24))

    # 🌐 Set token in cookie
    response = HTMLResponse(status_code=200)
    response.headers["HX-Redirect"] = redirect_url
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=60 * 60 * 24,  # 1 day
        secure=False,  # True in production with HTTPS
        samesite="Lax"
    )

    return response



@auth_router.get("/logout")
def logout():
    response = RedirectResponse(url="/auth/login-page")
    response.delete_cookie("access_token")
    response.set_cookie(key="logged_out", value="1", max_age=5)  # Expires in 5 seconds
    return response


# === USER INFO + ROLE ROUTES ===
@auth_router.get("/me")
def read_users_me(token: str = Depends(oauth2_scheme)):
    user_data = decode_token(token)
    return {"email": user_data.get("sub"), "role": user_data.get("role")}

@auth_router.get("/admin/dashboard")
def admin_dashboard(user=Depends(require_role("admin"))):
    return {"message": "Welcome Admin!", "email": user.get("sub")}
