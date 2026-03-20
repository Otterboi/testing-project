import sys, os
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../app")))

from app.db import get_db, _build_mongo_uri
from app.models import (
    PIIPatternConfig,
    SecretPatternConfig,
    AccessControlConfig,
    PolicyRule,
    PolicySet,
)


async def create_indexes(db):
    # create db indexes
    print("\n📊 Creating Indexes...")

    #  collection indexes
    await db.policies.create_index("id", unique=True)
    await db.policies.create_index([("active", 1), ("is_default", 1)])
    await db.policies.create_index("name")
    await db.policies.create_index("created_by")
    print("  ✅ Created 4 indexes for 'policies' collection")


async def seed_default_policy(db):
    print("\n📋 Creating Default Policies")

    # check if default exists
    existing = await db.policies.find_one({"is_default": True})
    if existing:
        print(f"⚠️ Default policy already exists: {existing['name']}")
        return

    # create default policy with enhanced patterns
    default_policy = PolicySet(
        name="Default Security Policy",
        description="Standard security policy for all projects",
        rules=[
            PolicyRule(
                name="Email Detection",
                description="Detects email addresses in code",  # detection will be implemented in the next task
                type="pii",
                severity="MEDIUM",
                action="redact",
                pii_patterns=[
                    PIIPatternConfig(
                        name="Standard Email",
                        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                        description="Email address pattern",
                        pii_type="email",
                        redaction_text="[EMAIL_REDACTED]",
                    )
                ],
                priority=100,
                tags=["pii", "contact"],
            ),
            PolicyRule(
                name="SSN Detection",
                description="Detects Social Security Numbers",
                type="pii",
                severity="HIGH",
                action="redact",
                pii_patterns=[
                    PIIPatternConfig(
                        name="SSN Pattern",
                        regex=r"\b\d{3}-\d{2}-\d{4}\b",
                        description="Social Security Number (XXX-XX-XXXX)",
                        pii_type="ssn",
                        redaction_text="[SSN_REDACTED]",
                    )
                ],
                priority=200,
                tags=["pii", "sensitive"],
            ),
            # Secret Rule: Private Keys
            PolicyRule(
                name="Private Key Detection",
                description="Detects private keys (RSA, EC, SSH)",
                type="secret",
                severity="CRITICAL",
                action="block",
                secret_patterns=[
                    SecretPatternConfig(
                        name="Private Key Header",
                        regex=r"-----BEGIN .*PRIVATE KEY-----",
                        description="Private key headers",
                        secret_type="private_key",
                    )
                ],
                priority=300,
                tags=["secret", "crypto"],
            ),
            PolicyRule(
                name="API Key Detection",
                description="Detects generic API keys",
                type="secret",
                severity="CRITICAL",
                action="redact",
                secret_patterns=[
                    SecretPatternConfig(
                        name="Generic API Key",
                        regex=r"(?i)api[_-]?key[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
                        description="Generic API key pattern",
                        secret_type="api_key",
                        entropy_threshold=4.5,  # Task 3 will calculate entropy
                    )
                ],
                priority=250,
                tags=["secret", "api"],
            ),
        ],
        access_controls=[
            # default access control config
            AccessControlConfig(
                path_pattern=r".*(?:payment|billing).*",
                allowed_roles=["senior_dev", "payment_team", "admin"],
                denied_roles=["intern", "contractor"],
                require_approval=True,
                description="Payment code requires senior developer access",
            )
        ],
        default_action="redact",
        version=1,
        active=True,
        is_default=True,
        created_by="system",
    )

    await db.policies.replace_one(
        {"name": default_policy.name}, default_policy.model_dump(), upsert=True
    )

    # display computed values -- len
    print(f"  ✅ New policy: {default_policy.name}")
    print(f"      ID: {default_policy.id}")
    print(f"      Total Rules: {default_policy.total_rules}")
    print(f"      PII Rules: {len([r for r in default_policy.rules if r.type == 'pii'])}")
    print(f"      Secret Rules: {len([r for r in default_policy.rules if r.type == 'secret'])}")
    print(f"      Access Controls: {len(default_policy.access_controls)}")


async def verify_setup(db):
    print("\n✔️  Verifying Setup...")

    collections = await db.list_collection_names()
    print(f"  Collections: {', '.join(collections)}")

    policy_count = await db.policies.count_documents({})
    print(f"  Policies: {policy_count} document(s)")

    indexes = await db.policies.index_information()
    print(f"  Indexes on 'policies': {len(indexes)}")

    default = await db.policies.find_one({"is_default": True})
    if default:
        print("\n  Default Policy:")
        print(f"    Name: {default['name']}")
        print(f"    Version: {default['version']}")
        print(f"    Rules: {len(default['rules'])}")


async def main():
    print("\n" + "=" * 70)
    print("🔧 SECURITY DATABASE INITIALIZATION")
    print("=" * 70)
    print(
        f"\nMongoDB: {_build_mongo_uri().split('@')[-1] if '@' in _build_mongo_uri() else _build_mongo_uri()}"
    )

    try:
        db = get_db()

        # 1. indexes
        await create_indexes(db)

        # 2. push policies list
        await seed_default_policy(db)

        # 3. verify setup
        await verify_setup(db)

        print("\n ✅ The policy schema is now set up in MongoDB.")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
