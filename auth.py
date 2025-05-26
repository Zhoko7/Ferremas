"""
Módulo de autenticación JWT para la API

Implementa:
- Autenticación básica con usuarios predefinidos
- Generación y validación de tokens JWT
- Control de acceso basado en roles
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

# Datos de usuarios de prueba (en producción usaría una base de datos con contraseñas hasheadas)
MOCK_USERS = {
    "javier_thompson": {
        "password": "aONF4d6aNBIxRjlgjBRRzrS",
        "role": "admin"
    },
    "ignacio_tapia": {
        "password": "f7rWChmQS1JYfThT",
        "role": "maintainer"
    },
    "stripe_sa": {
        "password": "dzkQqDL9XZH33YDzhmsf",
        "role": "service_account"
    },
}

# Configuración JWT (en producción estas claves deberían ser variables de entorno)
JWT_CONFIG = {
    "SECRET_KEY": "clave_super_secreta_para_token",
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_EXPIRE_MINUTES": 30
}

# Esquema OAuth2 para integración con Swagger UI
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Verifica las credenciales del usuario contra la base de datos mock"""
    user = MOCK_USERS.get(username)
    if user and user["password"] == password:
        return {"username": username, "role": user["role"]}
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Genera un token JWT con los datos del usuario y tiempo de expiración"""
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_CONFIG["ACCESS_TOKEN_EXPIRE_MINUTES"]))
    payload.update({"exp": expire})
    return jwt.encode(payload, JWT_CONFIG["SECRET_KEY"], algorithm=JWT_CONFIG["ALGORITHM"])

def decode_token(token: str) -> dict:
    """Valida y decodifica un token JWT"""
    try:
        payload = jwt.decode(token, JWT_CONFIG["SECRET_KEY"], algorithms=[JWT_CONFIG["ALGORITHM"]])
        if not all(key in payload for key in ["sub", "role"]):
            raise HTTPException(status_code=401, detail="Token inválido: faltan campos requeridos")
        return {"username": payload["sub"], "role": payload["role"]}
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Error de token: {str(e)}")

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Dependencia FastAPI para obtener el usuario actual desde el token"""
    return decode_token(token)

def require_roles(*allowed_roles):
    """Factory de dependencias para verificar roles del usuario"""
    def role_checker(user: dict = Depends(get_current_user)):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acceso denegado: privilegios insuficientes"
            )
        return user
    return role_checker