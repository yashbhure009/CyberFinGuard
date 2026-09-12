import hashlib
import json
import logging
import sys
from pathlib import Path

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# PROJECT IMPORTS
# ============================================================

from backend.database import db
from backend.ingestion.keycloak_ingestor import KeycloakIngestor


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(name)s:%(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# KEYCLOAK DATABASE LOADER
# ============================================================

class KeycloakDBLoader:

    def __init__(self, data):
        """
        Data structure comes directly from:
            KeycloakIngestor.collect()

        Expected structure:

        {
            "realm": "cyberfinguard",
            "users": [
                {
                    "id": "...",
                    "username": "...",
                    "first_name": "...",
                    "last_name": "...",
                    "email": "...",
                    "email_verified": True,
                    "enabled": True,
                    "mfa_enabled": True,
                    "roles": [...],
                    "groups": [...],
                    "clients": [...],
                    "authentication_events": [...]
                }
            ]
        }
        """

        self.data = data

    # ========================================================
    # USERS
    # ========================================================

    def load_users(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_users (
                user_id,
                username,
                first_name,
                last_name,
                email,
                email_verified,
                enabled,
                mfa_enabled
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)

            ON CONFLICT (user_id)
            DO UPDATE SET
                username = EXCLUDED.username,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name,
                email = EXCLUDED.email,
                email_verified = EXCLUDED.email_verified,
                enabled = EXCLUDED.enabled,
                mfa_enabled = EXCLUDED.mfa_enabled,
                updated_at = CURRENT_TIMESTAMP
        """

        count = 0

        for user in users:

            user_id = user.get("id")

            if not user_id:
                continue

            db.execute_query(
                query,
                (
                    user_id,
                    user.get("username"),
                    user.get("first_name"),
                    user.get("last_name"),
                    user.get("email"),
                    user.get("email_verified", False),
                    user.get("enabled", False),
                    user.get("mfa_enabled", False),
                )
            )

            count += 1

        logger.info("Users loaded: %s", count)

        return count

    # ========================================================
    # ROLES
    # ========================================================

    def load_roles(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_roles (
                role_id,
                role_name,
                description
            )
            VALUES (%s, %s, %s)

            ON CONFLICT (role_id)
            DO UPDATE SET
                role_name = EXCLUDED.role_name,
                description = EXCLUDED.description,
                updated_at = CURRENT_TIMESTAMP
        """

        count = 0

        # Roles are nested inside each user
        for user in users:

            roles = user.get("roles", [])

            for role in roles:

                role_id = role.get("id")
                role_name = role.get("name")

                if not role_id or not role_name:
                    continue

                db.execute_query(
                    query,
                    (
                        role_id,
                        role_name,
                        role.get("description"),
                    )
                )

                count += 1

        logger.info("Roles processed: %s", count)

        return count

    # ========================================================
    # GROUPS
    # ========================================================

    def load_groups(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_groups (
                group_id,
                group_name,
                group_path
            )
            VALUES (%s, %s, %s)

            ON CONFLICT (group_id)
            DO UPDATE SET
                group_name = EXCLUDED.group_name,
                group_path = EXCLUDED.group_path,
                updated_at = CURRENT_TIMESTAMP
        """

        count = 0

        # Groups are nested inside each user
        for user in users:

            groups = user.get("groups", [])

            for group in groups:

                group_id = group.get("id")
                group_name = group.get("name")

                if not group_id or not group_name:
                    continue

                db.execute_query(
                    query,
                    (
                        group_id,
                        group_name,
                        group.get("path"),
                    )
                )

                count += 1

        logger.info("Groups processed: %s", count)

        return count

    # ========================================================
    # USER → ROLE MAPPINGS
    # ========================================================

    def load_user_roles(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_user_roles (
                user_id,
                role_id
            )
            VALUES (%s, %s)

            ON CONFLICT (user_id, role_id)
            DO NOTHING
        """

        count = 0

        for user in users:

            user_id = user.get("id")

            if not user_id:
                continue

            roles = user.get("roles", [])

            for role in roles:

                role_id = role.get("id")

                if not role_id:
                    continue

                db.execute_query(
                    query,
                    (
                        user_id,
                        role_id,
                    )
                )

                count += 1

        logger.info(
            "User-role mappings processed: %s",
            count
        )

        return count

    # ========================================================
    # USER → GROUP MAPPINGS
    # ========================================================

    def load_user_groups(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_user_groups (
                user_id,
                group_id
            )
            VALUES (%s, %s)

            ON CONFLICT (user_id, group_id)
            DO NOTHING
        """

        count = 0

        for user in users:

            user_id = user.get("id")

            if not user_id:
                continue

            groups = user.get("groups", [])

            for group in groups:

                group_id = group.get("id")

                if not group_id:
                    continue

                db.execute_query(
                    query,
                    (
                        user_id,
                        group_id,
                    )
                )

                count += 1

        logger.info(
            "User-group mappings processed: %s",
            count
        )

        return count

    # ========================================================
    # AUTHENTICATION EVENTS
    # ========================================================

    def load_authentication_events(self):

        users = self.data.get("users", [])

        query = """
            INSERT INTO iam_authentication_events (
                event_id,
                user_id,
                event_type,
                event_time,
                event_timestamp,
                realm_id,
                client_id,
                session_id,
                ip_address,
                details
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                CASE
                    WHEN %s IS NOT NULL
                    THEN to_timestamp(%s / 1000.0)
                    ELSE NULL
                END,
                %s,
                %s,
                %s,
                %s,
                %s::jsonb
            )

            ON CONFLICT (event_id)
            DO NOTHING
        """

        count = 0

        for user in users:

            events = user.get(
                "authentication_events",
                []
            )

            for event in events:

                # ------------------------------------------------
                # Your ingestor already NORMALIZES events.
                #
                # Therefore we use:
                # time
                # type
                # realm_id
                # client_id
                # user_id
                # session_id
                # ip_address
                # details
                # ------------------------------------------------

                event_json = json.dumps(
                    event,
                    sort_keys=True,
                    default=str
                )

                event_id = hashlib.sha256(
                    event_json.encode("utf-8")
                ).hexdigest()

                event_time = event.get("time")

                db.execute_query(
                    query,
                    (
                        event_id,
                        event.get("user_id") or user.get("id"),
                        event.get("type"),
                        event_time,
                        event_time,
                        event_time,
                        event.get("realm_id") or self.data.get("realm"),
                        event.get("client_id"),
                        event.get("session_id"),
                        event.get("ip_address"),
                        json.dumps(
                            event.get("details", {})
                        ),
                    )
                )

                count += 1

        logger.info(
            "Authentication events processed: %s",
            count
        )

        return count

    # ========================================================
    # UPDATE LAST SEEN
    # ========================================================

    def update_last_seen(self):

        users = self.data.get("users", [])

        query = """
            UPDATE iam_users
            SET last_seen_at = (
                SELECT MAX(event_timestamp)
                FROM iam_authentication_events
                WHERE iam_authentication_events.user_id =
                      iam_users.user_id
            ),
            updated_at = CURRENT_TIMESTAMP
            WHERE user_id = %s
        """

        count = 0

        for user in users:

            user_id = user.get("id")

            if not user_id:
                continue

            db.execute_query(
                query,
                (user_id,)
            )

            count += 1

        logger.info(
            "Last-seen timestamps updated: %s",
            count
        )

    # ========================================================
    # LOAD ALL
    # ========================================================

    def load_all(self):

        logger.info("=" * 60)
        logger.info(
            "Loading Keycloak data into PostgreSQL"
        )
        logger.info("=" * 60)

        users = self.load_users()

        roles = self.load_roles()

        groups = self.load_groups()

        user_roles = self.load_user_roles()

        user_groups = self.load_user_groups()

        events = self.load_authentication_events()

        self.update_last_seen()

        logger.info("=" * 60)
        logger.info(
            "Keycloak database loading complete"
        )
        logger.info("=" * 60)

        return {
            "users": users,
            "roles": roles,
            "groups": groups,
            "user_role_mappings": user_roles,
            "user_group_mappings": user_groups,
            "authentication_events": events,
        }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("🔐 CyberFinGuard - Keycloak DB Loader")
    print("=" * 60)

    ingestor = KeycloakIngestor()

    try:

        # ----------------------------------------------------
        # CONNECT TO KALI
        # ----------------------------------------------------

        print("\n🔌 Connecting to Kali...")

        ingestor.connect_ssh()

        # ----------------------------------------------------
        # COLLECT KEYCLOAK DATA
        # ----------------------------------------------------

        print("📥 Collecting Keycloak data...")

        data = ingestor.collect()

        print(
            f"✅ Realm: {data.get('realm')}"
        )

        print(
            f"✅ Users collected: "
            f"{len(data.get('users', []))}"
        )

        # ----------------------------------------------------
        # LOAD INTO DATABASE
        # ----------------------------------------------------

        print("\n🗄️ Loading into PostgreSQL...")

        loader = KeycloakDBLoader(data)

        result = loader.load_all()

        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        print("\n" + "=" * 60)
        print("✅ KEYCLOAK → POSTGRESQL COMPLETE")
        print("=" * 60)

        print(
            f"Users:                 "
            f"{result['users']}"
        )

        print(
            f"Roles:                 "
            f"{result['roles']}"
        )

        print(
            f"Groups:                "
            f"{result['groups']}"
        )

        print(
            f"User-role mappings:    "
            f"{result['user_role_mappings']}"
        )

        print(
            f"User-group mappings:   "
            f"{result['user_group_mappings']}"
        )

        print(
            f"Authentication events: "
            f"{result['authentication_events']}"
        )

        print("=" * 60)

    except Exception as exc:

        logger.exception(
            "❌ Keycloak DB loading failed: %s",
            exc
        )

        raise

    finally:

        ingestor.close()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()