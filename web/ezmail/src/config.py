import os

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
LDAP_HOST = os.environ.get("LDAP_HOST", "localhost:1389")
SECRET_KEY = os.environ.get(
    "SECRET_KEY", "c39042a8731012ce0fbc06179044df22b493daefea4a58e606130b0127db325c"
)
