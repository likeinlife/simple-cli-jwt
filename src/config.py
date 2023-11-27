from datetime import timedelta
from pathlib import Path

BASEPATH = Path(__file__).parent.parent

RSA_PUBLIC_PATH = BASEPATH / 'keys/rsa.pub'
RSA_PRIVATE_PATH = BASEPATH / 'keys/rsa.private'

ACCESS_TOKEN_LIFETIME = timedelta(hours=1)
REFRESH_TOKEN_LIFETIME = timedelta(hours=1)
