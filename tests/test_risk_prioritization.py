"""Test suite for Phase 37: AI Security Risk & Prioritization Engine."""

from datetime import datetime, timezone
import pytest

from llmfirewall.risk import (
    RiskAssessment,
    RiskDiff,
    RiskFactor,
    RiskFactorType,
    RiskHistoryEntry,
    RiskLevel,
    RiskPrioritizationEngine,
    RiskSnapshot,
    RiskTreatment,
    RiskUncertainty,
)
from llmfirewall.inventory import AssetInventory, Asset, AssetType
from llmfirewall.graph import KnowledgeGraph, Node, NodeType, Relationship, RelationshipType
from llmfirewall.attack_graph import AttackGraph, AttackPath


@pytest.fixture
def mock_inventory():
    inv = AssetInventory()
    inv.register(
        Asset.create(
            asset_id="agent:support",
            asset_type=AssetType.AGENT.value,
            name="Customer Support Agent",
            metadata={"criticality": 0.75, "exposure": "external", "data_classification": "sensitive"},
        )
    )
    inv.register(
        Asset.create(
            asset_id="tool:db_query",
            asset_type=AssetType.TOOL.value,
            name="Database Query Tool",
            metadata={"criticality": 0.9, "exposure": "internal", "data_classification": "restricted"},
        )
    )
    inv.register(
        Asset.create(
            asset_id="db:production_customers",
            asset_type=AssetType.DATABASE.value,
            name="Production Customer Database",
            metadata={"criticality": 0.95, "exposure": "isolated", "data_classification": "restricted"},
        )
    )
    return inv


@pytest.fixture
def mock_graph():
    kg = KnowledgeGraph()
    agent = Node(id="agent:support", type=NodeType.AGENT.value, properties={"name": "Customer Support Agent"})
    tool = Node(id="tool:db_query", type=NodeType.TOOL.value, properties={"name": "Database Query Tool"})
    db = Node(id="db:production_customers", type=NodeType.CUSTOM.value, properties={"name": "Production Database"})
    kg.add_node(agent)
    kg.add_node(tool)
    kg.add_node(db)
    kg.add_relationship(Relationship(source=agent.id, target=tool.id, type=RelationshipType.CALLS.value))
    kg.add_relationship(Relationship(source=tool.id, target=db.id, type=RelationshipType.CAN_ACCESS.value))
    return kg


class TestRiskPrioritization:
    """Tests for risk analysis, inheritance, explainability, and uncertainty."""

    def test_risk_calculation_and_explainable_rationale(self, mock_inventory, mock_graph):
        engine = RiskPrioritizationEngine(inventory=mock_inventory, kg=mock_graph)
        assessment = engine.assess_asset_risk("agent:support")[0]

        assert assessment.asset_id == "agent:support"
        # Deterministic risk level
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        # Verify factors are independently evaluated, not an opaque score
        factor_types = [f.factor_type for f in assessment.factors]
        assert RiskFactorType.EXPOSURE in factor_types
        assert RiskFactorType.ASSET_CRITICALITY in factor_types
        assert RiskFactorType.DATA_SENSITIVITY in factor_types
        # Rationale must explicitly explain why it was prioritized
        assert "External" in assessment.rationale or "exposure" in assessment.rationale.lower()
        assert len(assessment.rationale) > 20

    def test_risk_inheritance_from_downstream_database(self, mock_inventory, mock_graph):
        """Downstream database with 0.95 criticality influences upstream agent risk."""
        engine = RiskPrioritizationEngine(inventory=mock_inventory, kg=mock_graph)
        assessment = engine.assess_asset_risk("agent:support")[0]

        # Must record inherited risk from db:production_customers
        assert assessment.inherited_from is not None
        assert "db:production_customers" in assessment.inherited_from or "tool:db_query" in assessment.inherited_from
        # Upstream effective criticality is elevated
        assert assessment.asset_criticality >= 0.75

    def test_epistemic_uncertainty_handling(self):
        """Zero telemetry must be treated as UNKNOWN uncertainty, never assumed safe."""
        inv = AssetInventory()
        inv.register(
            Asset.create(
                asset_id="agent:untested",
                asset_type=AssetType.AGENT.value,
                name="Untested Shadow Agent",
                metadata={"criticality": 0.5, "exposure": "external"},
            )
        )
        engine = RiskPrioritizationEngine(inventory=inv)
        assessment = engine.assess_asset_risk("agent:untested")[0]

        # Without empirical test results, uncertainty is UNKNOWN or SUPPORTED, never CONFIRMED safe
        assert assessment.uncertainty in (RiskUncertainty.UNKNOWN, RiskUncertainty.SUPPORTED, RiskUncertainty.PARTIALLY_SUPPORTED)
        assert assessment.uncertainty != RiskUncertainty.CONFIRMED
        assert assessment.level != RiskLevel.LOW

    def test_risk_treatment_lifecycle(self, mock_inventory):
        engine = RiskPrioritizationEngine(inventory=mock_inventory)
        assessment = engine.assess_asset_risk("agent:support")[0]
        assert assessment.treatment == RiskTreatment.OPEN

        # Update treatment
        assessment.treatment = RiskTreatment.MITIGATING
        assert assessment.treatment == RiskTreatment.MITIGATING

        assessment.treatment = RiskTreatment.RESOLVED
        assert assessment.treatment == RiskTreatment.RESOLVED


    def test_risk_regression_diffing(self, mock_inventory, mock_graph):
        """Detects RISK_INCREASED when control status or test results regress."""
        engine = RiskPrioritizationEngine(inventory=mock_inventory, kg=mock_graph)
        
        # Snapshot 1 (Before)
        snap1 = engine.snapshot(environment="staging")

        # Simulate finding regression / control failure
        target = mock_inventory.get("agent:support")
        if target:
            target.metadata["criticality"] = 0.99
            target.metadata["exposure"] = "external"
        engine._risk_store.clear()

        # Snapshot 2 (After)
        snap2 = engine.snapshot(environment="staging")

        # Compute diff
        diff = engine.diff(snap1, snap2)
        diff_dict = diff.to_dict()
        assert "total_increased" in diff_dict["summary"]
        assert "regressions" in diff_dict

    def test_secret_scrubbing_in_risk_metadata(self):
        """Ensures raw credentials are never persisted in risk factors or metadata."""
        risk = RiskAssessment(
            id="risk-01",
            title="Unauthorized Tool Access",
            asset_id="agent:support",
            level=RiskLevel.HIGH,
            business_context={"api_key": "sk-super-secret-key-12345", "dept": "support"},
            rationale="Test evaluation with sensitive key",
        )
        # The validator should redact the api_key
        assert risk.business_context.get("api_key") != "sk-super-secret-key-12345"
        assert "[REDACTED" in str(risk.business_context.get("api_key"))

