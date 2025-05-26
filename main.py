"""
API principal que integra:
- Autenticación JWT
- Datos de Ferremas
- Integración con BCCh
- Pagos con Stripe
"""

import os
from fastapi import FastAPI, HTTPException, Depends, Path, Query, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from fastapi.openapi.utils import get_openapi
import stripe
import requests
from fastapi import FastAPI

app = FastAPI()

print("¡Servidor iniciado!")  # <-- Usa paréntesis

@app.get("/")
def home():
    return {"message": "Funcionando"}


# Configuración
from auth import authenticate_user, create_access_token, require_roles
from banco_central import router as bcentral_router

# Configuración Stripe (la clave debería ser variable de entorno)
stripe.api_key = os.getenv("STRIPE_API_KEY")

app = FastAPI(
    title="API de Integración Ferremas",
    description="API para gestión de inventario, ventas y pagos",
    version="1.0.0"
)

# Registrar routers
app.include_router(bcentral_router)

# Configuración API Ferremas
FERREMAS_CONFIG = {
    "API_URL": "https://ea2p2assets-production.up.railway.app",
    "AUTH_TOKEN": "SaGrP9ojGS39hU9ljqbXxQ==",
    "HEADERS": {
        "x-authentication": "SaGrP9ojGS39hU9ljqbXxQ==",
        "Accept": "application/json",
        "Content-Type": "application/json"
    },
    "TIMEOUT": 10
}

# Modelos Pydantic
class Order(BaseModel):
    product_id: str
    quantity: int
    branch_id: str
    seller_id: int

class PaymentRequest(BaseModel):
    amount: int  # en centavos (ej: $10.00 = 1000)
    currency: str = "usd"
    description: str = "Pago en Ferremas"

def custom_openapi():
    """Personaliza la documentación OpenAPI para incluir autenticación JWT"""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Configurar esquema de seguridad
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    
    # Aplicar seguridad por defecto a todos los endpoints
    for path in openapi_schema["paths"].values():
        for method in path.values():
            if method.get("operationId") != "login":
                method.setdefault("security", [{"BearerAuth": []}])
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Endpoint de autenticación
@app.post("/auth/token", response_model=dict, tags=["Autenticación"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Autentica usuario y devuelve token JWT"""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    return {"access_token": token, "token_type": "bearer"}

# Endpoints públicos
@app.get("/products", tags=["Inventario"])
async def get_products():
    """Obtiene lista completa de productos"""
    try:
        response = requests.get(
            f"{FERREMAS_CONFIG['API_URL']}/data/articulos",
            headers=FERREMAS_CONFIG['HEADERS'],
            timeout=FERREMAS_CONFIG['TIMEOUT']
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(
            status_code=503,
            detail=f"Error al conectar con Ferremas: {str(e)}"
        )

@app.get("/products/{product_id}", tags=["Inventario"])
async def get_product(
    product_id: str = Path(..., description="ID del producto (ej: ART001)")
):
    """Obtiene detalles de un producto específico"""
    try:
        response = requests.get(
            f"{FERREMAS_CONFIG['API_URL']}/data/articulos/{product_id}",
            headers=FERREMAS_CONFIG['HEADERS'],
            timeout=FERREMAS_CONFIG['TIMEOUT']
        )
        response.raise_for_status()
        return response.json()
    except requests.HTTPError:
        raise HTTPException(status_code=404, detail="Producto no encontrado")
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=str(e))

# Endpoints protegidos
@app.get("/sellers", tags=["Ventas"], dependencies=[Depends(require_roles("admin", "maintainer"))])
async def get_sellers():
    """Obtiene lista de vendedores (requiere rol admin/maintainer)"""
    try:
        response = requests.get(
            f"{FERREMAS_CONFIG['API_URL']}/data/vendedores",
            headers=FERREMAS_CONFIG['HEADERS'],
            timeout=FERREMAS_CONFIG['TIMEOUT']
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=503, detail=str(e))

# Endpoint de pagos
@app.post("/payments", tags=["Pagos"])
async def create_payment(payment: PaymentRequest):
    """Crea un intento de pago con Stripe"""
    try:
        intent = stripe.PaymentIntent.create(
            amount=payment.amount,
            currency=payment.currency,
            description=payment.description,
            payment_method_types=["card"],
        )
        return {
            "client_secret": intent.client_secret,
            "status": intent.status,
            "amount": intent.amount
        }
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))