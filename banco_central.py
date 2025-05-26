"""
Módulo para consultar datos del Banco Central de Chile
"""

import bcchapi
import pandas as pd
from fastapi import APIRouter, HTTPException
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bcentral", tags=["Banco Central"])

# Configuración corregida - solo requiere api_key
try:
    bcch_client = bcchapi.Siete("Voidmero93")  # Solo API key como argumento posicional
except Exception as e:
    logger.error(f"Error al inicializar cliente BCCh: {str(e)}")
    bcch_client = None

@router.get("/buscar")
async def search_series(keyword: str):
    """
    Busca series de datos del BCCh por palabra clave
    """
    if not bcch_client:
        raise HTTPException(
            status_code=503,
            detail="Servicio BCCh no disponible"
        )
    
    try:
        results = bcch_client.buscar(keyword)
        return results.to_dict(orient="records")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al buscar en BCCh: {str(e)}"
        )

@router.get("/convertir")
async def currency_conversion(series_code: str, date: str, amount: float):
    """
    Convierte un monto usando el tipo de cambio del BCCh
    """
    if not bcch_client:
        raise HTTPException(
            status_code=503,
            detail="Servicio BCCh no disponible"
        )

    try:
        df = bcch_client.cuadro(
            series=[series_code],
            desde=date,
            hasta=date,
            frecuencia="D"
        )
        
        if df.empty or df[series_code].isna().all():
            raise HTTPException(
                status_code=404,
                detail="No hay datos disponibles para la fecha especificada"
            )
        
        exchange_rate = df[series_code].values[0]
        converted_amount = amount * exchange_rate

        return {
            "date": date,
            "series": series_code,
            "exchange_rate": exchange_rate,
            "original_amount": amount,
            "converted_amount": converted_amount
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error en conversión: {str(e)}"
        )