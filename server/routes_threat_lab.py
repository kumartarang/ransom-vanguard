import os
import io
from typing import Dict, Any, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from engine.detonation_lab import ThreatDetonationLab

class CustomPayloadRequest(BaseModel):
    payload_type: str = "script" # "script", "hex", "raw_text", "mock_note"
    filename: str = "custom_threat_payload.ps1"
    content: str
    simulate_execution: bool = True
    custom_threat_family: Optional[str] = None

class PresetDetonationRequest(BaseModel):
    preset_id: str
    simulate_execution: bool = True

def create_threat_lab_router(engine) -> APIRouter:
    router = APIRouter(prefix="/api/threat-lab", tags=["Threat Detonation Lab"])
    lab = ThreatDetonationLab(core_engine=engine, sandbox_dir="./simulator/sandbox")

    @router.get("/presets")
    async def get_threat_presets():
        """Returns the list of curated threat presets for testing."""
        presets = lab.get_presets()
        return {
            "status": "SUCCESS",
            "count": len(presets),
            "presets": [p.model_dump() for p in presets]
        }

    @router.post("/detonate-preset")
    async def detonate_preset(req: PresetDetonationRequest):
        """Detonates a curated threat preset in the sandbox."""
        matched_preset = next((p for p in lab.get_presets() if p.preset_id == req.preset_id), None)
        if not matched_preset:
            raise HTTPException(status_code=404, detail=f"Preset '{req.preset_id}' not found.")

        result = lab.process_threat_artifact(
            artifact_bytes=matched_preset.sample_content.encode('utf-8'),
            filename=matched_preset.filename,
            simulate_execution=req.simulate_execution,
            custom_threat_family=matched_preset.threat_family
        )
        return result.model_dump()

    @router.post("/insert-payload")
    async def insert_custom_payload(req: CustomPayloadRequest):
        """
        Inserts and detonates custom script code, raw encrypted bytes, or ransom notes.
        Triggers the full 6-Stage Autonomous Response Pipeline.
        """
        if not req.content or not req.content.strip():
            raise HTTPException(status_code=400, detail="Payload content cannot be empty.")

        artifact_bytes = req.content.encode('utf-8')
        result = lab.process_threat_artifact(
            artifact_bytes=artifact_bytes,
            filename=req.filename,
            simulate_execution=req.simulate_execution,
            custom_threat_family=req.custom_threat_family
        )
        return result.model_dump()

    @router.post("/upload-file")
    async def upload_threat_file(
        file: UploadFile = File(...),
        simulate_execution: bool = Form(True),
        custom_threat_family: Optional[str] = Form(None)
    ):
        """
        Uploads an arbitrary suspicious file (.exe, .ps1, .lockbit, .docx, .bin)
        and detonates it inside the monitored sandbox chamber.
        """
        try:
            file_bytes = await file.read()
            if not file_bytes:
                raise HTTPException(status_code=400, detail="Uploaded file is empty.")

            result = lab.process_threat_artifact(
                artifact_bytes=file_bytes,
                filename=file.filename or "uploaded_threat.bin",
                simulate_execution=simulate_execution,
                custom_threat_family=custom_threat_family
            )
            return result.model_dump()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Threat detonation error: {str(e)}")

    @router.get("/quarantine-vault")
    async def get_quarantined_items():
        """Returns all quarantined files and isolation metadata."""
        items = engine.quarantine_vault.get_all_quarantined()
        return {
            "status": "SUCCESS",
            "vault_dir": engine.quarantine_vault.vault_dir,
            "count": len(items),
            "items": [item.model_dump() for item in items]
        }

    return router
