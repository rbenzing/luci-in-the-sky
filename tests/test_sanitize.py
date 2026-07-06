from luci_sky.sanitize import sanitize


def test_sanitize_masks_sysauth_cookie():
    out = sanitize("Cookie: sysauth=ABCDEFGH1234567890secret")
    assert "ABCDEFGH***" in out
    assert "1234567890secret" not in out


def test_sanitize_masks_password_field():
    out = sanitize("luci_username=root&luci_password=hunter2")
    assert "luci_password=***" in out
    assert "hunter2" not in out


def test_sanitize_masks_authorization_header():
    out = sanitize("Authorization: Bearer sometoken")
    assert "Authorization: Bearer ***" in out
    assert "sometoken" not in out


def test_sanitize_truncates_to_max_len():
    assert len(sanitize("x" * 5000, max_len=100)) == 100
