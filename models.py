# Models for SQL tables

from sqlalchemy import Column, ForeignKey, Integer, String, Float
from db import Base
    
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True,index=True)
    userName = Column(String(80), nullable=False)
    email = Column(String(80), nullable=False, unique=True,index=True)
    password = Column(String(80), nullable=False)
    role = Column(String(10), nullable=False)

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True,index=True)
    name = Column(String(80), nullable=False)
    endpoint = Column(String(80), nullable=False)
    desc = Column(String(80), nullable=False)

class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True,index=True)
    name = Column(String(80), nullable=False)
    desc = Column(String(80), nullable=False)
    apiPermission = Column(String(80), nullable=False)
    limit = Column(Integer, nullable=False)

class SubscriptionTracker(Base):
    __tablename__ = "subscriptionTracker"

    id = Column(Integer, primary_key=True,index=True)
    userId = Column(Integer, ForeignKey("users.id"), nullable=False)
    planId = Column(Integer, ForeignKey("plans.id"), nullable=False)
    usage = Column(Integer, nullable=False)