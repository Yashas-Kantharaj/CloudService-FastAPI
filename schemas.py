# Request schemas for API's

from pydantic import BaseModel

class Users(BaseModel):
    userName: str
    email: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    email: str
    password: str

class Permission(BaseModel):
    name: str
    endpoint: str
    desc: str

class Plans(BaseModel):
    name: str
    desc: str
    apiPermission: str
    limit: int

class SubscriptionTracker(BaseModel):
    userId: int
    planId: int

