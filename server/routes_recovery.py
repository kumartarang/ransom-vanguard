from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List

def create_recovery_router(engine) -> APIRouter:
    router = APIRouter(prefix="/api/recovery", tags=["Recovery"])

    @router.post("/rollback-all")
    async def rollback_all_files():
        results = engine.snapshot_engine.restore_all()
        # Reset canaries
        engine.canary_manager.reset_canaries()
        restored = sum(1 for s in results.values() if s)
        return {
            "status": "SUCCESS",
            "message": f"Restored {restored} files from Micro-Snapshots. Tripwires re-armed.",
            "details": results
        }

    @router.get("/snapshots")
    async def get_snapshots_info():
        return {
            "total_snapshots": engine.snapshot_engine.get_snapshots_count(),
            "snapshots": [s.model_dump() for s in engine.snapshot_engine.snapshots.values()]
        }

    @router.get("/shadow-copies")
    async def get_shadow_copies():
        copies = engine.shadow_manager.list_shadow_copies()
        return [c.model_dump() for c in copies]

    @router.post("/shadow-copies/create")
    async def create_shadow_copy(drive: str = "C:"):
        success = engine.shadow_manager.create_shadow_copy(drive)
        return {"status": "SUCCESS" if success else "FAILED", "drive": drive}

    @router.get("/quarantine")
    async def get_quarantined_items():
        return [q.model_dump() for q in engine.quarantine_vault.get_all_quarantined()]

    @router.get("/decryptors")
    async def get_decryptors():
        return [d.model_dump() for d in engine.decrypt_advisor.get_all_tools()]

    @router.post("/network/restore")
    async def restore_network():
        res = engine.network_isolator.restore_network()
        return res.model_dump()

    return router
