import pytest


@pytest.fixture(autouse=True)
def isolated_trust_store(tmp_path_factory, monkeypatch):
    """Never touch the developer's real ~/.config/aegis-audit trust store."""
    store = tmp_path_factory.mktemp("trust") / "trusted_keys.json"
    monkeypatch.setenv("AEGIS_TRUST_STORE", str(store))
    monkeypatch.delenv("AEGIS_TRUSTED_FINGERPRINT", raising=False)
    monkeypatch.delenv("AEGIS_KEY_PASSPHRASE", raising=False)
    return store
