from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import User, ScanTarget
from schemas import UserCreate, UserLogin, UserOut, Token, TargetCreate, TargetOut
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)

app = FastAPI()


@app.on_event("startup")
def startup():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)


security = HTTPBearer()


@app.get("/")
def home():
    return {"message": "EganPurple App is running 🚀"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    new_user = User(
        email=user.email,
        hashed_password=hash_password(user.password),
        full_name=user.full_name,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token = create_access_token(data={"sub": db_user.email})

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")

        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user = db.query(User).filter(User.email == email).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    return user


@app.get("/me", response_model=UserOut)
def read_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/targets", response_model=TargetOut)
def create_target(
    target: TargetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    domain = target.domain.strip().lower()

    existing_target = (
        db.query(ScanTarget)
        .filter(
            ScanTarget.user_id == current_user.id,
            ScanTarget.domain == domain,
        )
        .first()
    )

    if existing_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target already exists",
        )

    new_target = ScanTarget(
        user_id=current_user.id,
        domain=domain,
        description=target.description,
    )

    db.add(new_target)
    db.commit()
    db.refresh(new_target)

    return new_target


@app.get("/targets", response_model=list[TargetOut])
def list_targets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    targets = (
        db.query(ScanTarget)
        .filter(ScanTarget.user_id == current_user.id)
        .order_by(ScanTarget.id.desc())
        .all()
    )

    return targets


@app.get("/targets/{target_id}", response_model=TargetOut)
def get_target(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target = (
        db.query(ScanTarget)
        .filter(
            ScanTarget.id == target_id,
            ScanTarget.user_id == current_user.id,
        )
        .first()
    )

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        )

    return target