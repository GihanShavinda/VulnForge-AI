from app.services.secret_patterns import scan_text

def test_detect_password_assignment_without_returning_in_api_shape():
    rows=scan_text("DB_PASSWORD=VerySecretPassword123","config.env")
    assert rows
    assert rows[0]["secret_type"]=="password_assignment"

def test_detect_ssh_private_key_category():
    text="-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAFAKEBODY123456\n-----END OPENSSH PRIVATE KEY-----"
    rows=scan_text(text,"id_test")
    assert any(x["secret_type"]=="ssh_private_key" for x in rows)
