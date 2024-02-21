from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from typing import List
import logging
import os
import sys
from getpass import getpass
import subprocess

import json

SECRET_KEY = "1cc4fd658d89fc20ec1963a4409acf56c47acdca4f6c51d4c854990f7dc5fb72"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
TIMEZONE_OFFSET = 3  # +3 hours

db = {
    "yahya": {
        "username": "yahya",
        "full_name": "yahya koyuncu",
        "email": "yahya@gmail.com",
        "hashed_client_key": "$2b$12$eKfH84t861CVq92zruCdgO4zf2sxsjiTvieRPoaLVEF/jeXldqXkS",
        "disabled": False,
        "is_admin": False
    },
    "admin": {
        "username": "admin",
        "full_name": "Admin User",
        "email": "admin@gmail.com",
        "hashed_client_key": "$2b$12$K20H2NsdC8ouyoWCqP7rvOPH4p5ig0Pxdihy/aydSc5eMClLGbRw6",
        "disabled": False,
        "is_admin": True
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    email: str or None = None
    full_name: str or None = None
    disabled: bool or None = None
    is_admin: bool or None = None
    hashed_client_key: str or None = None

class UserInDB(User):
    hashed_client_key: str

class UpdateClientKey(BaseModel):
    new_client_key: str

class UpdateServerKey(BaseModel):
    new_server_key: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()



def verify_password(plain_password, hashed_client_key):
    return pwd_context.verify(plain_password, hashed_client_key)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_client_key):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credential_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception
    return user

async def get_current_activate_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def generate_new_server_key():
    # Generate a new server key using openssl rand -hex 32
    result = subprocess.run(['openssl', 'rand', '-hex', '32'], stdout=subprocess.PIPE)
    new_server_key = result.stdout.decode().strip()
    return new_server_key

def convert_to_local_time(utc_time):
    return utc_time + timedelta(hours=TIMEZONE_OFFSET)


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_activate_user)):
    # Create a new User model without the hashed_client_key
    user_data = {
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "disabled": current_user.disabled,
        "is_admin": current_user.is_admin,
    }
    return User(**user_data)

@app.post("/update-client-key", response_model=str)
async def update_client_key(
    update_data: UpdateClientKey,
    current_user: UserInDB = Depends(get_current_activate_user)
):
    """
    Update client key securely.
    """
    try:
        # User (admin or normal) can update the client key
        if update_data.new_client_key:
            # Replace the following with your actual key update logic
            new_client_key = update_data.new_client_key
            # Log key update activity
            update_log = f"Client Key update by {current_user.username} at {convert_to_local_time(datetime.utcnow()).isoformat()}"
            print(update_log)

            # Persist the changes in the database
            db[current_user.username]["hashed_client_key"] = get_password_hash(new_client_key)
            # Create a new token with the updated information
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        create_access_token(data={"sub": current_user.username}, expires_delta=access_token_expires)
        return "Client Key updated successfully also a new token for the client is generated"
    except Exception as e:
        error_message = f"An error occurred in update_client_key: {str(e)}"
        logging.error(error_message)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
    


@app.get("/generate-new-server-key", response_model=str)
async def generate_new_server_key_route(
    current_user: UserInDB = Depends(get_current_activate_user)
):
    """
    Generate a new server key using openssl rand -hex 32.
    """
    # Check if the request is made by an admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to generate a new server key",
        )

    # Generate a new server key
    new_server_key = generate_new_server_key()

    return new_server_key

@app.get("/current-time")
async def get_current_time(current_user: UserInDB = Depends(get_current_user)):
    return {"current_time": convert_to_local_time(datetime.utcnow()).isoformat()}


