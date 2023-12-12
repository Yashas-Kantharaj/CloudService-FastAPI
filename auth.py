# Authentication

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
import bcrypt

security = HTTPBearer()


# define a base model for the token
class TokenPayload(BaseModel):
    sub: int = None
    role: str = None


# function to check the user's role based on the bearer token
async def check_user_role(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Bearer token missing")
    try:
        token = credentials.credentials
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        token_data = TokenPayload(**payload)
        if token_data.role not in ["admin","user"]:
            raise HTTPException(status_code=403, detail="Not authorized to access this resource")
        return token_data
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
def password_hash(password):
    # converting password to array of bytes 
    bytes = password.encode('utf-8') 
  
    # generating the salt 
    salt = bcrypt.gensalt() 
  
    # Hashing the password 
    hash = bcrypt.hashpw(bytes, salt) 
    return hash

def password_check(savedPassword, password):
    # encoding entered password
    userBytes = password.encode('utf-8')

    # checking password
    result = bcrypt.checkpw(userBytes, savedPassword)
    return result