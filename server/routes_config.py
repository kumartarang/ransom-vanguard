from fastapi import APIRouter, Body
from typing import Dict, Any

def create_config_router(engine) -> APIRouter:
    router = APIRouter(prefix="/api/config", tags=["Configuration"])

    @router.get("")
    async def get_config():
        return {
            "app_name": engine.config.get("app_name", "RansomVanguard"),
            "version": engine.config.get("version", "1.0.0"),
            "policy": engine.policy_engine.policy.model_dump(),
            "monitored_paths": engine.fs_sensor.monitored_paths,
            "entropy_threshold": engine.fs_sensor.entropy_threshold,
            "canaries": engine.canary_manager.get_status(),
            "is_engine_running": engine.is_running
        }

    @router.post("/policy")
    async def update_policy(policy_data: Dict[str, Any] = Body(...)):
        engine.policy_engine.update_policy(**policy_data)
        return {"status": "SUCCESS", "updated_policy": engine.policy_engine.policy.model_dump()}

    return router
