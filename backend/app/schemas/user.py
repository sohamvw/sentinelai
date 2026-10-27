from pydantic import BaseModel, EmailStr
from typing import Optional


class UserRegisterRequest(BaseModel):
    first_name: str
    last_name: Optional[str] = ""
    username: str
    email: EmailStr
    password: str


class UserLoginRequest(BaseModel):
    email: str
    password: str


class VerifyOTPRequest(BaseModel):
    email: str
    code: str


class ResendOTPRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str


class CheckResetOtpRequest(BaseModel):
    email: str
    code: str


class UserProfileUpdateRequest(BaseModel):
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class SupportTicketCreateRequest(BaseModel):
    user_id: Optional[str] = ""
    user_name: str
    user_email: str
    subject: str
    description: str




class UserResponse(BaseModel):
    user_id: str
    first_name: str
    last_name: str
    username: str
    email: str
    is_verified: bool = False
    provider: str = "email"


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    requires_verification: bool = False



