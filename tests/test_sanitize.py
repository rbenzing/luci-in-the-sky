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


def test_sanitize_masks_dict_repr_password():
    out = sanitize(str({"luci_username": "root", "luci_password": "supersecret123"}))
    assert "supersecret123" not in out
    assert "root" in out  # username is not a secret; only the password is masked


def test_sanitize_masks_json_password():
    out = sanitize('{"luci_password": "hunter2", "other": "keep"}')
    assert "hunter2" not in out
    assert "keep" in out


def test_sanitize_masks_password_with_apostrophe():
    out = sanitize(str({"luci_password": "it's", "user": "root"}))
    assert "it's" not in out
    assert "'s" not in out           # no suffix leak
    assert "user" in out


def test_sanitize_masks_password_with_embedded_quote():
    import json
    out = sanitize(json.dumps({"luci_password": 'ab"cd', "keep": "x"}))
    assert "ab" not in out and "cd" not in out
    assert "keep" in out
