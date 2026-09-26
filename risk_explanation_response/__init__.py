# CyberGuard Risk Explanation and Response Package
from risk_explanation_response.risk_scorer import calculate_campaign_risk
from risk_explanation_response.explainer import generate_explanation
from risk_explanation_response.response_engine import recommend_response, RESPONSE_PLAYBOOKS
from correlation.correlator import Campaign


def evaluate_campaign(campaign: Campaign) -> Campaign:
    """
    Executes the full downstream analysis pipeline on a campaign:
    1. Risk Scoring (computes score and risk level)
    2. Response Recommendation (assigns action and playbook)
    3. Explainable AI Generation (creates executive summary & narrative)
    """
    calculate_campaign_risk(campaign)
    recommend_response(campaign)
    generate_explanation(campaign)
    return campaign


__all__ = [
    "calculate_campaign_risk",
    "generate_explanation",
    "recommend_response",
    "RESPONSE_PLAYBOOKS",
    "evaluate_campaign"
]
