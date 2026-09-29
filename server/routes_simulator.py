from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from simulator.attack_simulator import SafeAttackSimulator

def create_simulator_router(engine) -> APIRouter:
    router = APIRouter(prefix="/api/simulator", tags=["Simulator"])
    simulator = SafeAttackSimulator(sandbox_dir="./simulator/sandbox", canary_dir="./canary_vault")

    @router.post("/populate")
    async def populate_sandbox():
        count = simulator.populate_sandbox()
        # Also snapshot clean baseline
        engine.snapshot_engine.snapshot_directory(simulator.sandbox_dir)
        return {"status": "SUCCESS", "message": f"Populated {count} enterprise mock files into sandbox.", "files_created": count}

    @router.post("/attack/canary-trip")
    async def simulate_canary_trip():
        res = simulator.run_canary_trip_simulation()
        return res.model_dump()

    @router.post("/attack/entropy-burst")
    async def simulate_entropy_burst():
        res = simulator.run_entropy_burst_simulation()
        return res.model_dump()

    @router.post("/attack/extension-mutation")
    async def simulate_extension_mutation(ext: str = ".lockbit"):
        res = simulator.run_extension_mutation_simulation(target_ext=ext)
        return res.model_dump()

    @router.post("/attack/ransom-note")
    async def simulate_ransom_note():
        res = simulator.run_ransom_note_drop_simulation()
        return res.model_dump()

    @router.post("/attack/full-killchain")
    async def simulate_full_attack():
        res = simulator.run_full_kill_chain_simulation()
        return res.model_dump()

    return router
