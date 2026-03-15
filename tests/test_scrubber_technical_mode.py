import scrubber


class _Result:
    def __init__(self, entity_type: str, start: int, end: int, score: float):
        self.entity_type = entity_type
        self.start = int(start)
        self.end = int(end)
        self.score = float(score)


def test_scrub_prompt_enables_technical_mode_and_disables_person_location_entities(monkeypatch):
    captured = {}

    def _fake_detect(text: str, _engine, *, technical_mode: bool = False):
        captured["text"] = text
        captured["technical_mode"] = technical_mode
        return []

    monkeypatch.setattr(scrubber, "_presidio_engine", lambda: object())
    monkeypatch.setattr(scrubber, "_presidio_detect", _fake_detect)

    prompt = "import httpx\nasync def fetch():\n    return await asyncio.sleep(0)"
    out = scrubber.scrub_prompt(prompt)

    assert out["technical_mode"] is True
    assert captured["technical_mode"] is True
    assert out["cleaned_prompt"] == prompt


def test_person_and_location_require_confidence_above_threshold(monkeypatch):
    prompt = "Alice traveled to Nairobi."
    alice_start = prompt.index("Alice")
    nairobi_start = prompt.index("Nairobi")

    def _fake_detect(_text: str, _engine, *, technical_mode: bool = False):
        assert technical_mode is False
        return [
            _Result("PERSON", alice_start, alice_start + len("Alice"), 0.80),
            _Result("LOCATION", nairobi_start, nairobi_start + len("Nairobi"), 0.79),
        ]

    monkeypatch.setattr(scrubber, "_presidio_engine", lambda: object())
    monkeypatch.setattr(scrubber, "_presidio_detect", _fake_detect)

    out = scrubber.scrub_prompt(prompt)
    assert out["cleaned_prompt"] == prompt
    assert out["placeholders"] == {}
    assert out["detections"] == []


def test_python_syntax_identifiers_are_not_redacted(monkeypatch):
    prompt = "from email.utils import parsedate_to_datetime\nclient = httpx.AsyncClient()"
    parsedate_start = prompt.index("parsedate_to_datetime")
    async_client_start = prompt.index("AsyncClient")

    def _fake_detect(_text: str, _engine, *, technical_mode: bool = False):
        assert technical_mode is True
        return [
            _Result("PERSON", parsedate_start, parsedate_start + len("parsedate_to_datetime"), 0.99),
            _Result("LOCATION", async_client_start, async_client_start + len("AsyncClient"), 0.99),
        ]

    monkeypatch.setattr(scrubber, "_presidio_engine", lambda: object())
    monkeypatch.setattr(scrubber, "_presidio_detect", _fake_detect)

    out = scrubber.scrub_prompt(prompt)
    assert out["cleaned_prompt"] == prompt
    assert out["placeholders"] == {}


def test_location_entities_are_logged_but_not_redacted(monkeypatch):
    prompt = "What is the birth rate in Jamaica currently?"
    location = "Jamaica"
    location_start = prompt.index(location)

    def _fake_detect(_text: str, _engine, *, technical_mode: bool = False):
        assert technical_mode is False
        return [_Result("LOCATION", location_start, location_start + len(location), 0.99)]

    monkeypatch.setattr(scrubber, "_presidio_engine", lambda: object())
    monkeypatch.setattr(scrubber, "_presidio_detect", _fake_detect)

    out = scrubber.scrub_prompt(prompt)
    assert out["cleaned_prompt"] == prompt
    assert out["placeholders"] == {}
    assert len(out["detections"]) == 1
    assert out["detections"][0]["entity_type"] == "LOCATION"
    assert out["detections"][0]["redacted"] is False


def test_sensitive_entities_remain_redacted_in_technical_mode(monkeypatch):
    prompt = (
        "import httpx\n"
        "server_ip = '10.0.0.1'\n"
        "contact = 'jane.doe@example.com'\n"
        "client = httpx.AsyncClient()"
    )

    def _fake_detect(text: str, _engine, *, technical_mode: bool = False):
        assert technical_mode is True
        ip = "10.0.0.1"
        ip_start = text.index(ip)
        return [_Result("IP_ADDRESS", ip_start, ip_start + len(ip), 0.99)]

    monkeypatch.setattr(scrubber, "_presidio_engine", lambda: object())
    monkeypatch.setattr(scrubber, "_presidio_detect", _fake_detect)

    out = scrubber.scrub_prompt(prompt)
    cleaned = out["cleaned_prompt"]

    assert out["technical_mode"] is True
    assert "[EMAIL_ADDRESS_1]" in cleaned
    assert "[IP_ADDRESS_1]" in cleaned
    assert "client = httpx.AsyncClient()" in cleaned
    assert cleaned.count("\n") == prompt.count("\n")
