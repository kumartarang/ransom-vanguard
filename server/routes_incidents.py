from fastapi import APIRouter, HTTPException, Query, Response
from typing import List, Dict, Any, Optional
from engine.analyze.attack_graph import AttackIncident
from engine.recover.forensic_exporter import ForensicReportExporter

def create_incidents_router(engine) -> APIRouter:
    router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

    @router.get("", response_model=List[Dict[str, Any]])
    async def get_all_incidents():
        incidents = engine.attack_graph.get_all_incidents()
        return [i.model_dump() for i in incidents]

    @router.get("/active", response_model=Optional[Dict[str, Any]])
    async def get_active_incident():
        incident = engine.attack_graph.get_active_incident()
        if incident:
            return incident.model_dump()
        return None

    @router.get("/{incident_id}", response_model=Dict[str, Any])
    async def get_incident(incident_id: str):
        incident = engine.attack_graph.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident.model_dump()

    @router.get("/{incident_id}/report", response_class=Response)
    async def get_incident_html_report(incident_id: str):
        incident = engine.attack_graph.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        html = ForensicReportExporter.generate_html_report(incident)
        return Response(content=html, media_type="text/html")

    @router.get("/alerts/recent")
    async def get_recent_alerts(limit: int = Query(50, ge=1, le=200)):
        alerts = engine.alert_dispatcher.get_recent_alerts(limit=limit)
        return [a.model_dump() for a in alerts]

    @router.get("/forensics/audit-log")
    async def get_forensic_audit_log(limit: int = Query(50, ge=1, le=200)):
        return engine.audit_logger.read_recent_entries(limit=limit)

    return router
