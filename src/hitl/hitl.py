"""
Lab 11 - Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass

HIGH_VALUE_TRANSFER_VND = 10_000_000
HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
    "password_reset",
    "identity_change",
    "account_change",
    "fraud_complaint",
]

@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str
    confidence: float
    reason: str
    priority: str
    requires_human: bool

class ConfidenceRouter:
    """Route agent responses based on confidence and risk level."""
    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float, action_type: str = "general", amount: int | float | None = None) -> RoutingDecision:
        """Route a response based on confidence score and action type."""
        if amount is not None and amount > HIGH_VALUE_TRANSFER_VND:
            return RoutingDecision("escalate", confidence, f"High-value transfer over {HIGH_VALUE_TRANSFER_VND:,} VND", "high", True)
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", confidence, f"High-risk action: {action_type}", "high", True)
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", confidence, "High confidence", "low", False)
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", confidence, "Medium confidence - needs review", "normal", True)
        return RoutingDecision("escalate", confidence, "Low confidence - escalating", "high", True)

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-value transfer",
        "trigger": "Transfer amount exceeds 10,000,000 VND",
        "hitl_model": "human-in-the-loop",
        "context_needed": "Amount, recipient, account ownership, fraud signals, and recent transfer history",
        "example": "Customer requests a 20,000,000 VND transfer to a new recipient.",
    },
    {
        "id": 2,
        "name": "Identity or account change",
        "trigger": "Change phone, email, password, address, or close account",
        "hitl_model": "human-as-tiebreaker",
        "context_needed": "KYC status, identity evidence, login risk, and account impact",
        "example": "Customer asks to change registered phone number and email.",
    },
    {
        "id": 3,
        "name": "Low confidence or judge failure",
        "trigger": "Confidence < 0.70 or judge verdict FAIL",
        "hitl_model": "human-on-the-loop",
        "context_needed": "Original question, model response, judge scores, and failure reason",
        "example": "Assistant gives an unsupported financial claim or off-topic answer.",
    },
]

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()
    test_cases = [
        ("Balance inquiry", 0.95, "general", None),
        ("Interest rate question", 0.82, "general", None),
        ("Ambiguous request", 0.55, "general", None),
        ("Transfer 20,000,000 VND", 0.98, "transfer_money", 20_000_000),
        ("Close my account", 0.91, "close_account", None),
    ]
    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)
    for scenario, conf, action_type, amount in test_cases:
        decision = router.route(scenario, conf, action_type, amount)
        print(f"{scenario:<25} {conf:<6.2f} {action_type:<18} {decision.action:<15} {decision.priority:<10} {'Yes' if decision.requires_human else 'No'}")
    print("=" * 80)

def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
