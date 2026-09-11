from pathlib import Path
from cyberark_aim.vault import Vault, Secret


def test_put_and_get_roundtrip(tmp_path: Path):
    v = Vault(tmp_path / "v.enc", tmp_path / "a.log", "pw")
    v.put(Secret(account="a1", username="u", password="p"))
    got = v.get("a1")
    assert got is not None
    assert got.username == "u"


def test_rotate_updates_password(tmp_path: Path):
    v = Vault(tmp_path / "v.enc", tmp_path / "a.log", "pw")
    v.put(Secret(account="a1", username="u", password="old"))
    assert v.rotate("a1", "new")
    assert v.get("a1").password == "new"
