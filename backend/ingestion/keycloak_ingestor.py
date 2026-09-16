import os
import json
import logging
from dataclasses import dataclass
import requests  # 👈 SSH ki jagah yeh use karo
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)

@dataclass
class KeycloakConfig:
    keycloak_url: str = os.getenv("KEYCLOAK_URL", "http://localhost:8090")
    keycloak_admin: str = os.getenv("KEYCLOAK_ADMIN", "admin")
    keycloak_password: str = os.getenv("KEYCLOAK_PASSWORD", "admin")
    keycloak_realm: str = os.getenv("KEYCLOAK_REALM", "master")

class KeycloakIngestor:
    def __init__(self, config=None):
        self.config = config or KeycloakConfig()
        self.token = None

    # ❌ connect_ssh() — HATA DO
    # ❌ run_remote_command() — HATA DO

    # ✅ Direct HTTP calls
    def get_admin_token(self):
        url = f"{self.config.keycloak_url}/realms/master/protocol/openid-connect/token"
        data = {
            "username": self.config.keycloak_admin,
            "password": self.config.keycloak_password,
            "grant_type": "password",
            "client_id": "admin-cli",
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        self.token = response.json()["access_token"]
        logger.info("Keycloak authentication successful.")
        return self.token

    def get_users(self):
        url = f"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users?max=1000"
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def get_user_roles(self, user_id):
        url = f"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users/{user_id}/role-mappings/realm"
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else []

    def get_user_groups(self, user_id):
        url = f"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users/{user_id}/groups"
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else []

    def get_authentication_events(self, user_id=None, max_events=100):
        url = f"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/events"
        params = {"first": 0, "max": max_events}
        if user_id:
            params["user"] = user_id
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(url, headers=headers, params=params)
        return response.json() if response.status_code == 200 else []

    def normalize_event(self, event):
        if not isinstance(event, dict):
            return None
        return {
            "time": event.get("time"),
            "type": event.get("type"),
            "realm_id": event.get("realmId"),
            "client_id": event.get("clientId"),
            "user_id": event.get("userId"),
            "session_id": event.get("sessionId"),
            "ip_address": event.get("ipAddress"),
            "details": event.get("details", {}),
        }

    def collect(self):
        self.get_admin_token()
        users = self.get_users()
        enriched_users = []

        for user in users:
            user_id = user.get("id")
            logger.info(f"Collecting IAM context for: {user.get('username')}")

            roles = self.get_user_roles(user_id)
            normalized_roles = [
                {"id": r.get("id"), "name": r.get("name"), "description": r.get("description")}
                for r in roles if isinstance(r, dict)
            ]

            groups = self.get_user_groups(user_id)
            normalized_groups = [
                {"id": g.get("id"), "name": g.get("name"), "path": g.get("path")}
                for g in groups if isinstance(g, dict)
            ]

            raw_events = self.get_authentication_events(user_id=user_id)
            normalized_events = [
                self.normalize_event(e) for e in raw_events if self.normalize_event(e) is not None
            ]

            enriched_users.append({
                "id": user_id,
                "username": user.get("username"),
                "first_name": user.get("firstName"),
                "last_name": user.get("lastName"),
                "email": user.get("email"),
                "email_verified": user.get("emailVerified", False),
                "enabled": user.get("enabled", False),
                "mfa_enabled": bool(user.get("totp")),
                "roles": normalized_roles,
                "groups": normalized_groups,
                "authentication_events": normalized_events,
            })

        return {"realm": self.config.keycloak_realm, "users": enriched_users}

    def close(self):
        pass  
    # ============================================================
# MAIN (Standalone test ke liye)
# ============================================================

def main():
    ingestor = KeycloakIngestor()
    try:
        data = ingestor.collect()
        print()
        print("=" * 60)
        print("✅ Keycloak ingestion successful.")
        print(f"Realm: {data['realm']}")
        print(f"Users collected: {len(data['users'])}")
        print("=" * 60)

        for user in data["users"]:
            print()
            print(f"User: {user['username']}")
            print(f"  ID: {user['id']}")
            print(f"  Email: {user['email']}")
            print(f"  Enabled: {user['enabled']}")
            print(f"  MFA: {user['mfa_enabled']}")
            print(f"  Roles: {len(user['roles'])}")
            print(f"  Groups: {len(user['groups'])}")
            print(f"  Events: {len(user['authentication_events'])}")
    except Exception as e:
        logger.error(f"❌ Keycloak ingestion failed: {e}")
    finally:
        ingestor.close()


if __name__ == "__main__":
    main()# SSH nahi hai ab