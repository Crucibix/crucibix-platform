"""Liveness/readiness endpoints for ECS health checks and k8s-style probes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/healthz", summary="Liveness")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", summary="Readiness")
async def readyz() -> dict[str, str]:
    # Services override/extend to check DB + dependencies before accepting traffic.
    return {"status": "ready"}
