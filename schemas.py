from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str | None = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None = None

    model_config = {
        "from_attributes": True
    }


class Token(BaseModel):
    access_token: str
    token_type: str


class TargetCreate(BaseModel):
    domain: str
    description: str | None = None


class TargetOut(BaseModel):
    id: int
    domain: str
    description: str | None = None
    user_id: int

    model_config = {
        "from_attributes": True
    }