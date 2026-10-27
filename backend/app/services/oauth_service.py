import os
import json
import urllib.request
import urllib.parse
from typing import Dict, Any, Optional

# Pull OAuth config from the central settings object (app.core.config) so the
# redirect URIs and secrets aren't parsed independently here and in config.py.
# This used to be two sources of truth that could drift apart.
from app.core.config import settings as app_settings

GOOGLE_CLIENT_ID = app_settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = app_settings.GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI = app_settings.GOOGLE_REDIRECT_URI

GITHUB_CLIENT_ID = app_settings.GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET = app_settings.GITHUB_CLIENT_SECRET
GITHUB_REDIRECT_URI = app_settings.GITHUB_REDIRECT_URI


class OAuthService:

    @staticmethod
    def get_google_auth_url() -> str:
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "online",
            "prompt": "select_account"
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"

    @staticmethod
    def get_github_auth_url() -> str:
        params = {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": GITHUB_REDIRECT_URI,
            "scope": "user:email read:user"
        }
        return f"https://github.com/login/oauth/authorize?{urllib.parse.urlencode(params)}"

    @classmethod
    def exchange_google_code(cls, code: str) -> Dict[str, Any]:
        token_url = "https://oauth2.googleapis.com/token"
        data = urllib.parse.urlencode({
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code"
        }).encode("utf-8")

        req = urllib.request.Request(token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            tokens = json.loads(resp.read().decode("utf-8"))
            access_token = tokens["access_token"]

        userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        user_req = urllib.request.Request(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
        with urllib.request.urlopen(user_req, timeout=15) as user_resp:
            profile = json.loads(user_resp.read().decode("utf-8"))

        return {
            "first_name": profile.get("given_name", profile.get("name", "GoogleUser")),
            "last_name": profile.get("family_name", ""),
            "email": profile.get("email"),
            "provider": "google"
        }

    @classmethod
    def exchange_github_code(cls, code: str) -> Dict[str, Any]:
        token_url = "https://github.com/login/oauth/access_token"
        data = urllib.parse.urlencode({
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI
        }).encode("utf-8")

        req = urllib.request.Request(token_url, data=data, headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            tokens = json.loads(resp.read().decode("utf-8"))
            access_token = tokens["access_token"]

        user_url = "https://api.github.com/user"
        user_req = urllib.request.Request(user_url, headers={"Authorization": f"Bearer {access_token}", "User-Agent": "SentinelAI-App"})
        with urllib.request.urlopen(user_req, timeout=15) as user_resp:
            profile = json.loads(user_resp.read().decode("utf-8"))

        # Fetch primary email if not public in profile
        email = profile.get("email")
        if not email:
            email_req = urllib.request.Request("https://api.github.com/user/emails", headers={"Authorization": f"Bearer {access_token}", "User-Agent": "SentinelAI-App"})
            with urllib.request.urlopen(email_req, timeout=15) as email_resp:
                emails_list = json.loads(email_resp.read().decode("utf-8"))
                for em in emails_list:
                    if em.get("primary"):
                        email = em.get("email")
                        break

        names = (profile.get("name") or profile.get("login", "GitHubUser")).split(" ", 1)
        return {
            "first_name": names[0],
            "last_name": names[1] if len(names) > 1 else "",
            "email": email or f"{profile.get('login')}@users.noreply.github.com",
            "provider": "github"
        }
