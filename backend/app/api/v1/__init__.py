"""
API v1 Router Registration
============================
Aggregates all v1 sub-routers into a single APIRouter
mounted at /api/v1 in main.py.
"""

from fastapi import APIRouter

from app.api.v1 import alerts, chat, health, incidents

api_router = APIRouter()

# Health (no prefix — mounted at /api/v1/health)
api_router.include_router(health.router)

# Domain routers
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(chat.router)
