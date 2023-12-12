from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from db import get_db, engine
import schemas as schemas
import models as models
import auth as auth
import jwt
import json

app = FastAPI()

models.Base.metadata.create_all(bind = engine)

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def createUser(user: schemas.Users, db: Session = Depends(get_db)):

    check_user = db.query(models.User).filter(models.User.email == user.email).first()

    if not check_user:
        new_user =  models.User(userName=user.userName, email=user.email, password=auth.password_hash(user.password), role=user.role)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    else:
        raise HTTPException(status_code=400, detail="User already exists!")
        
@app.post("/login")
async def login(user: schemas.UserLogin, db: Session = Depends(get_db)):

    if not user.email or not user.password:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    checkUser = db.query(models.User).filter(models.User.email == user.email).first()

    if not checkUser:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    if auth.password_check(checkUser.password, user.password):
        # Generate a JWT token
        access_token = jwt.encode({"sub": checkUser.id, "role": checkUser.role}, "secret", algorithm="HS256")

        # Return the access token and user details
        return {"token" : access_token, 
                "detail" : "Successfully logged in"}
    else:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

@app.post("/permissions", status_code=status.HTTP_201_CREATED)
async def addPermission(permission: schemas.Permission, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")

    newPermission = db.query(models.Permission).filter(models.Permission.name == permission.name).first()

    if not newPermission:
        new_Permission =  models.Permission(name=permission.name, endpoint=permission.endpoint, desc=permission.desc)
        db.add(new_Permission)
        db.commit()
        db.refresh(new_Permission)
        return new_Permission
    else:
        raise HTTPException(status_code=400, detail="Permission already exists!")
    
@app.patch("/permissions/{perId}")
async def updatePermission(perId: int, permission: schemas.Permission, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    selectedPermission = db.query(models.Permission).filter(models.Permission.id == perId).first()

    if selectedPermission:
        selectedPermission.name = permission.name
        selectedPermission.endpoint = permission.endpoint
        selectedPermission.desc = permission.desc
        db.add(selectedPermission)
        db.commit()
        db.refresh(selectedPermission)
        return selectedPermission
    else:
        raise HTTPException(status_code=400, detail="Permission doesn't exists!")
    
@app.delete("/permissions/{perId}")
async def deletePermission(perId: int, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    permission = db.query(models.Permission).filter(models.Permission.id == perId).first()

    if permission:
        db.delete(permission)
        db.commit()
        return permission
    else:
        raise HTTPException(status_code=400, detail="Permission doesn't exists!")
    
@app.post("/plan", status_code=status.HTTP_201_CREATED)
async def addPlan(plan: schemas.Plans, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    newPlan = db.query(models.Plan).filter(models.Plan.name == plan.name).first()

    if not newPlan:
        new_Plan =  models.Plan(name=plan.name, desc=plan.desc, apiPermission=plan.apiPermission, limit=plan.limit)
        db.add(new_Plan)
        db.commit()
        db.refresh(new_Plan)
        return new_Plan
    else:
        raise HTTPException(status_code=400, detail="Plan already exists!")
    
@app.patch("/plan/{planId}")
async def updatePlan(planId: int, plan: schemas.Plans, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    newPlan = db.query(models.Plan).filter(models.Plan.id == planId).first()

    if newPlan:
        newPlan.name=plan.name 
        newPlan.desc=plan.desc
        newPlan.apiPermission=plan.apiPermission
        newPlan.limit=plan.limit
        db.add(newPlan)
        db.commit()
        db.refresh(newPlan)
        return newPlan
    else:
        raise HTTPException(status_code=400, detail="Plan doesn't exists!")
    
@app.delete("/plan/{planId}")
async def deletePlan(planId: int, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    newPlan = db.query(models.Plan).filter(models.Plan.id == planId).first()

    if newPlan:
        db.delete(newPlan)
        db.commit()
        return newPlan
    else:
        raise HTTPException(status_code=400, detail="Plan doesn't exists!")

# Allows users to subscribe to plans
@app.post("/subscriptions", status_code=status.HTTP_201_CREATED)
async def addSubscriptions(subscriptions: schemas.SubscriptionTracker, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    
    newSubscription = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == subscriptions.userId).first()

    if newSubscription:
        db.delete(newSubscription)
        db.commit()

    new_Subscription =  models.SubscriptionTracker(userId=subscriptions.userId, planId=subscriptions.planId, usage=0)
    db.add(new_Subscription)
    db.commit()
    db.refresh(new_Subscription)
    return new_Subscription
 
# Returns User's subscriptions details
@app.get("/subscriptions/{userId}")
async def getSubscriptions(userId: int, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    
    getSub = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == userId).first()
    sub = None
    if getSub:
        sub = db.query(models.Plan).filter(models.Plan.id == getSub.planId).first()
    if sub:
        return sub
    else:
        raise HTTPException(status_code=400, detail="User doesn't have a subscription!")
    
# Update user's subscriptions details
@app.patch("/subscriptions/{userId}")
async def updateSubscriptions(userId: int, subscriptions: schemas.SubscriptionTracker, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    if token_data.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this resource")
    
    updateSubscription = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == userId).first()

    if updateSubscription:
        updateSubscription.userId=subscriptions.userId
        updateSubscription.planId=subscriptions.planId
        db.add(updateSubscription)
        db.commit()
        db.refresh(updateSubscription)
        return updateSubscription
    else:
        raise HTTPException(status_code=400, detail="Subscriptions doesn't exists for the user!")
    
# Returns user's usage and limit for his subscription
@app.get("/usage/{userId}/limit")
async def checkLimit(userId: int,  db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):

    usage = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == userId).first()
    limit = None
    if usage: 
        limit = db.query(models.Plan).filter(models.Plan.id == usage.planId).first()

    if limit and usage:
        return {"usage" : usage.usage,
                "limit" : limit.limit}
    else:
        raise HTTPException(status_code=400, detail="User is not subscribed to any plan")
    
# Returns user's plan and his permissions
@app.get("/access/{userId}")
async def accessControl(userId: int, db: Session = Depends(get_db), token_data: auth.TokenPayload = Depends(auth.check_user_role)):
    sub = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == userId).first()
    plan = None
    if sub:
        plan = db.query(models.Plan).filter(models.Plan.id == sub.planId).first()
    
    if sub and plan:
        return {"plan" : plan,
                "permission" : plan.apiPermission}
    else:
        raise HTTPException(status_code=400, detail="User is not subscribed to any plan")

# Cloud service endpoints
@app.get("/cloudAPI-1")
async def feature1(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-1")
    return "Feature 1 for pro sub"

@app.get("/cloudAPI-2")
async def feature2(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-2")
    return "Feature 2 for pro sub"

@app.get("/cloudAPI-3")
async def feature3(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-3")
    return "Feature 3 for pro sub"

@app.get("/cloudAPI-4")
async def feature4(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-4")
    return "Feature 4 for premium sub"

@app.get("/cloudAPI-5")
async def feature5(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-5")
    return "Feature 5 for premium sub"

@app.get("/cloudAPI-6")
async def feature6(token_data: auth.TokenPayload = Depends(auth.check_user_role), db: Session = Depends(get_db)):
    usageCheck(token_data.sub, db, "cloudAPI-6")
    return "Feature 6 for premium sub"

# Function to check usage and permission to access the cloud service endpoints
def usageCheck(userId: id, db: Session, endpoint):
    usage = db.query(models.SubscriptionTracker).filter(models.SubscriptionTracker.userId == userId).first()
    permission = db.query(models.Permission).filter(models.Permission.endpoint == endpoint).first()

    if usage and permission:
        plan = db.query(models.Plan).filter(models.Plan.id == usage.planId).first()
        list = json.loads(plan.apiPermission)
        print("list",list)
        print(permission.id not in list)
        if (usage.usage > plan.limit) or (permission.id not in list):
            raise HTTPException(status_code=403, detail="User has crossed his subscription limit")

        usage.usage = usage.usage + 1
        db.add(usage)
        db.commit()
        db.refresh(usage)

    else:
        raise HTTPException(status_code=401, detail="Not authorized to access this resource")