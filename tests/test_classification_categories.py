from risk import compute_risk_score


def test_risk_categories_and_severity_shape():
    entity_counts = {
        "EMAIL_ADDRESS": 2,
        "CREDIT_CARD": 1,
        "API_KEY": 1,
        "PHI_TERM": 2,
        "IP_ADDRESS": 1,
    }
    pack = compute_risk_score(entity_counts, injection_detected=False)
    categories = pack["risk_categories"]

    assert categories["PII"] >= 2
    assert categories["FIN"] == 1
    assert categories["SECRETS"] == 1
    assert categories["HEALTH"] == 2
    assert categories["IP"] == 1
    assert pack["severity"] in {"Low", "Med", "High", "Critical"}
    assert isinstance(pack["risk_score"], int)


def test_public_location_is_analytics_only_with_no_enforcement_risk():
    pack = compute_risk_score({"LOCATION": 2}, injection_detected=False)
    categories = pack["risk_categories"]

    assert pack["risk_score"] == 0
    assert pack["risk_level"] == "LOW"
    assert pack["severity"] == "Low"
    assert categories["PUBLIC"] == 2
    assert categories["PII"] == 0
