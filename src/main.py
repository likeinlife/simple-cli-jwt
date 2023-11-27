import argparse
import json
import uuid
from dataclasses import dataclass

from .jwt_service import get_jwt_service


@dataclass
class JwtArgs:
    user_id: str 
    email: str
    roles: list[str]

@dataclass
class Args:
    user_id: uuid.UUID | None
    email: str | None
    roles: list[str]

    def get_jwt_args(self) -> JwtArgs:
        return JwtArgs(
            user_id=str(self.user_id) if self.user_id else str(uuid.uuid4()),
            email=self.email if self.email else 'default@mail.ru',
            roles=self.roles,
        )



def parse_args() -> Args:
    parser = argparse.ArgumentParser()

    parser.add_argument("--user_id", "-id", type=uuid.UUID)
    parser.add_argument("--email", "-e", type=str)
    parser.add_argument("--roles", "-r", nargs=-1)

    args = parser.parse_args()

    return Args(
        user_id=args.user_id,
        email=args.email,
        roles=args.roles,
    )


def main():
    args = parse_args()
    jwt_service = get_jwt_service()

    jwt_args = args.get_jwt_args()

    access_token = jwt_service.encode_access_token(jwt_args.user_id, jwt_args.email, jwt_args.roles)
    refresh_token = jwt_service.encode_refresh_token(jwt_args.user_id, jwt_args.email, jwt_args.roles)

    token_dict = dict(access_token=access_token, refresh_token=refresh_token)

    print(json.dumps(token_dict, ensure_ascii=False, indent=4))

