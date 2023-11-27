import uuid
from datetime import datetime, timedelta

import jwt

from .config import (ACCESS_TOKEN_LIFETIME, REFRESH_TOKEN_LIFETIME,
                     RSA_PRIVATE_PATH, RSA_PUBLIC_PATH)
from .errors import InvalidScopeError
from .misc import ACCESS_TOKEN, REFRESH_TOKEN


class JWTService:
    def __init__(
        self,
        private_key: str,
        public_key: str,
        access_token_lifetime: timedelta,
        refresh_token_lifetime: timedelta,
    ) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.access_token_lifetime = access_token_lifetime
        self.refresh_token_lifetime = refresh_token_lifetime

    def encode_access_token(self, user_id: str, email: str, roles: list[str]) -> str:
        payload = {
            "exp": datetime.utcnow() + self.access_token_lifetime,
            "iat": datetime.utcnow(),
            "scope": ACCESS_TOKEN,
            "sub": user_id,
            "email": email,
            "roles": roles,
            "jti": str(uuid.uuid4()),
        }

        return jwt.encode(
            payload=payload,
            key=self.private_key,
            algorithm="RS256",
        )

    def decode_access_token(self, token: str) -> dict:
        """
        Decode jwt token.

        Raises:
            jwt.ExpiredSignatureError: token expired
            jwt.InvalidTokenError: incorrect token
            InvalidScopeError: invalid scope
        """
        payload: dict = jwt.decode(token, self.public_key, algorithms=["RS256"])
        if payload["scope"] == ACCESS_TOKEN:
            return payload
        raise InvalidScopeError(payload["scope"])

    def decode_token(self, token: str) -> dict:
        """
        Decode any jwt token.

        Raises:
            jwt.ExpiredSignatureError: token expired
            jwt.InvalidTokenError: incorrect token
        """
        payload: dict = jwt.decode(token, self.public_key, algorithms=["RS256"])
        return payload

    def encode_refresh_token(self, user_id: str, email: str, roles: list[str]) -> str:
        payload = {
            "exp": datetime.utcnow() + self.access_token_lifetime,
            "iat": datetime.utcnow(),
            "scope": REFRESH_TOKEN,
            "sub": user_id,
            "email": email,
            "roles": roles,
            "jti": str(uuid.uuid4()),
        }

        return jwt.encode(
            payload=payload,
            key=self.private_key,
            algorithm="RS256",
        )

    def refresh_token(self, refresh_token: str) -> str:
        """
        Generate new token by refresh token.

        Raises:
            jwt.ExpiredSignatureError: token expired
            jwt.InvalidTokenError: incorrect token
            InvalidScopeError: invalid scope
        """
        payload: dict = jwt.decode(refresh_token, self.public_key, algorithms=["RS256"])
        if payload["scope"] == REFRESH_TOKEN:
            user_id = payload["sub"]
            return self.encode_access_token(user_id, payload["email"], payload["roles"])
        raise InvalidScopeError(payload["scope"])

    def get_timedelta(self, token: str) -> timedelta:
        """
        Get timedelta until token expire.

        Raises:
            jwt.ExpiredSignatureError: token expired
            jwt.InvalidTokenError: incorrect token
        """
        payload: dict = jwt.decode(token, self.public_key, algorithms=["RS256"])
        expire_datetime = datetime.fromtimestamp(payload["exp"])
        return expire_datetime - datetime.utcnow()


def get_jwt_service() -> JWTService:
    with open(RSA_PRIVATE_PATH, "r") as priv_obj:
        with open(RSA_PUBLIC_PATH, "r") as pub_obj:
            return JWTService(
                private_key=priv_obj.read(),
                public_key=pub_obj.read(),
                access_token_lifetime=ACCESS_TOKEN_LIFETIME,
                refresh_token_lifetime=REFRESH_TOKEN_LIFETIME,
            )
