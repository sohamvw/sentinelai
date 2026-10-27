from fastapi import APIRouter, HTTPException, Depends, Query
import os
import uuid
from typing import Any, Dict

from app.schemas.user import (
    UserRegisterRequest, UserLoginRequest, VerifyOTPRequest,
    ResendOTPRequest, ResetPasswordRequest, CheckResetOtpRequest,
    UserProfileUpdateRequest, SupportTicketCreateRequest,
    UserResponse, AuthTokenResponse
)
from app.core.database import UserRepository, SupportTicketRepository, verify_password, generate_otp
from app.services.email_service import EmailService
from app.services.audit_log_service import AuditLogService
from app.services.oauth_service import OAuthService
from app.core.config import settings

router = APIRouter()


def _is_oauth_domain_allowed(email: str) -> bool:
    """
    GitHub OAuth is restricted to a configured allowlist of email domains
    (default: apsit.edu.in). Email/password signup/login is NOT restricted.
    """
    if not email or "@" not in email:
        return False
    domain = email.rsplit("@", 1)[-1].strip().lower()
    allowed = {
        d.strip().lower()
        for d in settings.APSIT_ALLOWED_OAUTH_DOMAINS.split(",")
        if d.strip()
    }
    return domain in allowed


@router.post("/support-ticket")
def create_support_ticket(request: SupportTicketCreateRequest):
    ticket = SupportTicketRepository.create_ticket(
        user_id=request.user_id or "",
        user_name=request.user_name,
        user_email=request.user_email,
        subject=request.subject,
        description=request.description
    )

    notify_email = settings.ADMIN_NOTIFY_EMAIL
    EmailService.send_support_ticket_email(
        admin_email=notify_email,
        reporter_name=request.user_name,
        reporter_email=request.user_email,
        subject=request.subject,
        description=request.description,
        ticket_id=ticket["ticket_id"]
    )

    return {
        "message": "Your ticket has been submitted, we'll get back to you soon.",
        "ticket": ticket
    }



@router.post("/update-profile", response_model=UserResponse)
def update_profile(request: UserProfileUpdateRequest):
    user = UserRepository.get_by_email(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if request.current_password or request.new_password:
        if not request.current_password or not verify_password(request.current_password, user.get("password_hash", "")):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        if not request.new_password:
            raise HTTPException(status_code=400, detail="New password is required.")
        UserRepository.update_password(request.email, request.new_password)

    updated_user = UserRepository.update_profile(
        email=request.email,
        first_name=request.first_name,
        last_name=request.last_name,
        username=request.username
    )

    return UserResponse(
        user_id=updated_user["id"],
        first_name=updated_user["first_name"],
        last_name=updated_user.get("last_name", ""),
        username=updated_user.get("username", updated_user["email"].split("@")[0]),
        email=updated_user["email"],
        is_verified=bool(updated_user.get("is_verified")),
        provider=updated_user.get("provider", "email")
    )



@router.post("/register", response_model=AuthTokenResponse)
def register(request: UserRegisterRequest):
    existing = UserRepository.get_by_email(request.email)
    if existing:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please sign in."
        )


    user_record = UserRepository.create_user(
        first_name=request.first_name,
        last_name=request.last_name,
        username=request.username,
        email=request.email,
        password=request.password,
        provider="email"
    )

    # // TEMP DISABLED - re-enable before final submission
    # otp_code = user_record.get("verification_code")
    # email_sent = EmailService.send_verification_email(
    #     recipient_email=request.email,
    #     first_name=request.first_name,
    #     otp_code=otp_code
    # )

    UserRepository.set_verified(request.email)

    user_resp = UserResponse(
        user_id=user_record["id"],
        first_name=user_record["first_name"],
        last_name=user_record["last_name"],
        username=user_record["username"],
        email=user_record["email"],
        is_verified=True,
        provider="email"
    )

    return AuthTokenResponse(
        access_token=f"sentinel_jwt_token_{user_record['id']}",
        user=user_resp,
        requires_verification=False
    )




@router.post("/verify-otp", response_model=AuthTokenResponse)
def verify_otp(request: VerifyOTPRequest):
    success = UserRepository.verify_otp(request.email, request.code)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired 6-digit verification code (expires in 10 mins).")

    user = UserRepository.get_by_email(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user_resp = UserResponse(
        user_id=user["id"],
        first_name=user["first_name"],
        last_name=user["last_name"],
        username=user.get("username", user["email"].split("@")[0]),
        email=user["email"],
        is_verified=True,
        provider=user.get("provider", "email")
    )

    return AuthTokenResponse(
        access_token=f"sentinel_verified_token_{user['id']}",
        user=user_resp,
        requires_verification=False
    )


@router.get("/check-username")
def check_username(username: str = Query(...)):
    if len(username.strip()) < 3:
        return {"available": False, "reason": "Username must be at least 3 characters long."}
    if not username.replace("_", "").isalnum():
        return {"available": False, "reason": "Alphanumeric and underscores only."}
    
    user = UserRepository.get_by_username(username.strip())
    if user:
        return {"available": False, "reason": "Username is already taken."}
    return {"available": True, "reason": "Username is available!"}


@router.post("/forgot-password-otp")
def forgot_password_otp(request: ResendOTPRequest):
    user = UserRepository.get_by_email(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="No account registered with this email address.")

    user_record = UserRepository.create_user(
        first_name=user["first_name"],
        last_name=user.get("last_name", ""),
        username=user.get("username", user["email"].split("@")[0]),
        email=user["email"],
        password=None,
        provider=user.get("provider", "email")
    )

    otp_code = user_record.get("verification_code")

    EmailService.send_verification_email(
        recipient_email=user["email"],
        first_name=user["first_name"],
        otp_code=otp_code
    )

    response = {
        "message": f"Password reset 6-digit OTP code sent to {request.email}"
    }
    # Dev-only: the OTP is returned in the response ONLY if the env var
    # RETURN_OTP_IN_RESPONSE=true is set. Leave it unset in production.
    if os.getenv("RETURN_OTP_IN_RESPONSE", "").lower() == "true":
        response["verification_code"] = otp_code
    return response


@router.post("/check-reset-otp")
def check_reset_otp(request: CheckResetOtpRequest):
    """
    Non-destructive OTP check used by the reset-password flow. Confirms that
    the 6-digit code matches the one currently stored for the email and has
    not expired, WITHOUT clearing the stored code. This lets the frontend
    reveal the password fields only after a code match, and then make a
    single /reset-password call that consumes the OTP.
    """
    if not UserRepository.check_otp(request.email, request.code):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired 6-digit verification code."
        )
    return {"valid": True}


@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    success = UserRepository.verify_otp(request.email, request.code)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired 6-digit verification code.")

    user = UserRepository.get_by_email(request.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    UserRepository.update_password(request.email, request.new_password)
    UserRepository.set_verified(request.email)

    user_resp = UserResponse(
        user_id=user["id"],
        first_name=user["first_name"],
        last_name=user.get("last_name", ""),
        username=user.get("username", user["email"].split("@")[0]),
        email=user["email"],
        is_verified=True,
        provider=user.get("provider", "email")
    )

    return AuthTokenResponse(
        access_token=f"sentinel_jwt_token_{user['id']}",
        user=user_resp,
        requires_verification=False
    )



@router.post("/login", response_model=AuthTokenResponse)
def login(request: UserLoginRequest):
    user = UserRepository.get_by_email(request.email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="No account registered with this email — Sign Up instead."
        )

    if not verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # if not user.get("is_verified"):
    #     otp_code = user.get("verification_code") or generate_otp()
    #     user_resp = UserResponse(
    #         user_id=user["id"],
    #         first_name=user["first_name"],
    #         last_name=user["last_name"],
    #         username=user.get("username", user["email"].split("@")[0]),
    #         email=user["email"],
    #         is_verified=False,
    #         provider=user.get("provider", "email")
    #     )
    #     return AuthTokenResponse(
    #         access_token=f"sentinel_unverified_token_{user['id']}",
    #         user=user_resp,
    #         requires_verification=True
    #     )



    user_resp = UserResponse(
        user_id=user["id"],
        first_name=user["first_name"],
        last_name=user["last_name"],
        username=user.get("username", user["email"].split("@")[0]),
        email=user["email"],
        is_verified=True,
        provider=user.get("provider", "email")
    )

    return AuthTokenResponse(
        access_token=f"sentinel_jwt_token_{user['id']}",
        user=user_resp,
        requires_verification=False
    )


@router.get("/oauth/{provider}")
def oauth_redirect(provider: str):
    """
    Returns the OAuth provider's authorization URL. Real exchange is done in
    OAuthService so the redirect/start logic and the token exchange logic
    share configuration.
    """
    if provider == "google":
        return {"url": OAuthService.get_google_auth_url()}
    elif provider == "github":
        return {"url": OAuthService.get_github_auth_url()}
    else:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider.")


from fastapi.responses import RedirectResponse, JSONResponse
import json
import urllib.parse


@router.get("/oauth/{provider}/callback")
def oauth_callback(provider: str, code: str = Query(...)):
    """
    Exchanges OAuth authorization code for user info, creates/logs in user,
    and redirects to the frontend dashboard.

    GitHub OAuth is gated to the apsit.edu.in domain (configurable via
    APSIT_ALLOWED_OAUTH_DOMAINS). Email/password signup and login are NOT
    gated.
    """
    if provider not in ["google", "github"]:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider.")

    profile: Dict[str, Any] = {}
    try:
        if provider == "google":
            if not settings.GOOGLE_CLIENT_SECRET:
                raise RuntimeError("Google OAuth client secret not configured")
            profile = OAuthService.exchange_google_code(code)
        elif provider == "github":
            if not settings.GITHUB_CLIENT_SECRET:
                raise RuntimeError("GitHub OAuth client secret not configured")
            profile = OAuthService.exchange_github_code(code)
    except Exception as e:
        print(f"[OAUTH ERROR] {provider} token exchange failed: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"OAuth provider {provider} returned an error. Please try again.",
        )

    email = (profile.get("email") or "").strip().lower()
    if not email or email.endswith("@users.noreply.github.com") and provider == "github":
        # GitHub returns @users.noreply.github.com when no primary email is
        # available — refuse it because we can't verify the apsit domain
        # without a real email.
        raise HTTPException(
            status_code=400,
            detail=(
                "Could not retrieve a verified email from GitHub. "
                "Make sure your primary email is public in GitHub Settings → Emails, "
                "or grant the 'user:email' scope on consent."
            ),
        )

    # GitHub OAuth domain gate. Email/password flows are unrestricted.
    if provider == "github" and not _is_oauth_domain_allowed(email):
        allowed = settings.APSIT_ALLOWED_OAUTH_DOMAINS
        raise HTTPException(
            status_code=403,
            detail=(
                f"GitHub sign-in is restricted to {allowed} accounts. "
                f"The email on your GitHub account is {email}."
            ),
        )

    first_name = profile.get("first_name") or provider.capitalize()
    last_name = profile.get("last_name") or "User"
    username = (email.split("@")[0] or f"{provider}_user_{uuid.uuid4().hex[:6]}")[:64]

    user = UserRepository.get_by_email(email)
    if not user:
        user = UserRepository.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=None,
            provider=provider,
        )
    UserRepository.set_verified(email)
    user["is_verified"] = True

    user_resp = {
        "user_id": user["id"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "username": user.get("username", username),
        "email": user["email"],
        "is_verified": True,
        "provider": provider,
    }

    token = f"sentinel_oauth_token_{user['id']}"
    user_json_encoded = urllib.parse.quote(json.dumps(user_resp))
    frontend_url = f"{settings.FRONTEND_BASE_URL.rstrip('/')}/#oauth-success?token={token}&user={user_json_encoded}"
    return RedirectResponse(url=frontend_url)