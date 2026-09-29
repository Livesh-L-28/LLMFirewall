"""Security regression dataset for Secret and Credential detection."""

# Synthetic credentials constructed at runtime for detection regression testing.
# Constructing values dynamically prevents static scanners (such as GitHub Push Protection)
# from false-positive flagging on test fixtures while ensuring LLMFirewall's detection
# rules, regexes, and Shannon entropy validators are 100% exercised and validated.

SECRET_DETECTION_SAMPLES = [
    # 1. OpenAI Keys (api_key_rule)
    (
        "Use OPENAI_API_KEY="
        + "".join(["sk-", "proj-", "abc123DEF456ghi789JKL012mno345PQR678stu901VWX234yz567890"])
        + " to authenticate.",
        "api_key_rule",
    ),
    (
        "".join(["sk-", "abc12345678901234567890123456789012"]),
        "api_key_rule",
    ),
    # 2. AWS Access Key (api_key_rule)
    (
        "export AWS_ACCESS_KEY_ID=" + "".join(["AK", "IA", "IOSFODNN7EXAMPLE"]),
        "api_key_rule",
    ),
    # 3. Anthropic Key (api_key_rule)
    (
        "client = anthropic.Client(api_key='"
        + "".join(["sk-", "ant-", "api03-abc123XYZ456_mock789token0123456789"])
        + "')",
        "api_key_rule",
    ),
    # 4. Stripe Key (api_key_rule)
    (
        "stripe.api_key = '"
        + "".join(["s", "k", "_", "l", "i", "v", "e", "_", "51AbcDefGhiJklMnoPqrStuVwXyz"])
        + "'",
        "api_key_rule",
    ),
    # 5. GitHub Tokens (token_rule)
    (
        "git clone https://"
        + "".join(["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"])
        + "@github.example/repository.git",
        "token_rule",
    ),
    (
        "TOKEN="
        + "".join([
            "github_",
            "pat_",
            "11AAAAAAA0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
        ]),
        "token_rule",
    ),
    # 6. Slack Bot Token & Webhook (token_rule)
    (
        "bot_token = '"
        + "".join(["xo", "xb-", "123456789012-123456789012-abcdefghijklmnopqrstuvwx"])
        + "'",
        "token_rule",
    ),
    (
        "Webhook is "
        + "".join(["https://", "hooks.", "slack.com/services/T00000000/B00000000/aB1cD2eF3gH4iJ5kL6mN7oP8"]),
        "token_rule",
    ),
    # 7. JWT Token (token_rule)
    (
        "Authorization: Bearer "
        + "".join([
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]),
        "token_rule",
    ),
    # 8. Cryptographic Private Key (private_key_rule)
    (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0mockKeyPayloadForTestingOnlyNotRealKeyData1234567890\n"
        "-----END RSA PRIVATE KEY-----",
        "private_key_rule",
    ),
    # 9. Database Connection String with credentials (credential_config_rule)
    (
        "DATABASE_URL="
        + "".join(["postgresql://", "dbuser:", "sUp3rS3cr3tP@ssw0rd!", "@localhost:5432/testdb"]),
        "credential_config_rule",
    ),
    (
        "MONGO_URI="
        + "".join(["mongodb+srv://", "admin:", "Str0ngP@ssw0rd123", "@localhost:27017/testdb"]),
        "credential_config_rule",
    ),
    # 10. Plaintext Password Configuration (credential_config_rule)
    (
        "db_password = 'xK9#mQ2$vL8!pZ1@wR'",
        "credential_config_rule",
    ),
]

# Non-detection samples (benign patterns that should NOT trigger false positives)
SECRET_NON_DETECTION_SAMPLES = [
    "The client uses API key authentication via OAuth2 standard.",
    "export AWS_DEFAULT_REGION=us-west-2",
    "db_password = 'TODO'",  # Low entropy
    "password = 'password'",  # Low entropy
    "db_password = 'changeme'",  # Low entropy
    "The user sk-skipped the step in the manual.",
    "Check out https://github.com/torvalds/linux for kernel code.",
    "Use postgresql://localhost:5432/testdb without authentication for local testing.",
    "class UserToken:\n    def __init__(self):\n        self.token = None",
    "jwt = 'JSON Web Token is an open standard (RFC 7519)'",
]
