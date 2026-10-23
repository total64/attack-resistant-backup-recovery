from .risk_engine import RiskAssessment, RiskEngine, RiskEvent


class RiskService:
    def __init__(self, engine: RiskEngine | None = None):
        self.engine = engine or RiskEngine()

    def assess(self, event_id: str, host_id: str, indicators: dict[str, bool]) -> RiskAssessment:
        return self.engine.assess(RiskEvent(event_id, host_id, indicators))
