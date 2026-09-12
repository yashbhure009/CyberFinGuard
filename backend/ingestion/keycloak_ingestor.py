import os
import json
import logging
from dataclasses import dataclass

import paramiko
from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s:%(name)s:%(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass
class KeycloakConfig:
    """
    Configuration for Keycloak ingestion.
    """

    # --------------------------------------------------------
    # Kali SSH
    # --------------------------------------------------------

    ssh_host: str = os.getenv(
        "KALI_HOST",
        "192.168.56.101"
    )

    ssh_port: int = int(
        os.getenv(
            "KALI_SSH_PORT",
            "22"
        )
    )

    ssh_username: str = os.getenv(
        "KALI_USERNAME",
        "kali"
    )

    ssh_password: str = os.getenv(
        "KALI_PASSWORD",
        "kali"
    )

    # --------------------------------------------------------
    # Keycloak
    # --------------------------------------------------------

    keycloak_url: str = os.getenv(
        "KEYCLOAK_URL",
        "http://127.0.0.1:8080"
    )

    keycloak_admin: str = os.getenv(
        "KEYCLOAK_ADMIN",
        "admin"
    )

    keycloak_password: str = os.getenv(
        "KEYCLOAK_PASSWORD",
        ""
    )

    keycloak_realm: str = os.getenv(
        "KEYCLOAK_REALM",
        "cyberfinguard"
    )


# ============================================================
# KEYCLOAK INGESTOR
# ============================================================

class KeycloakIngestor:
    """
    Connects to Kali through SSH and retrieves IAM data
    from Keycloak.
    """

    def __init__(self, config=None):

        self.config = config or KeycloakConfig()

        self.ssh = None

    # ========================================================
    # SSH CONNECTION
    # ========================================================

    def connect_ssh(self):
        """
        Connect to Kali Linux using SSH.
        """

        logger.info("Connecting to Kali...")

        self.ssh = paramiko.SSHClient()

        self.ssh.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.ssh.connect(
            hostname=self.config.ssh_host,
            port=self.config.ssh_port,
            username=self.config.ssh_username,
            password=self.config.ssh_password,
            timeout=10
        )

        logger.info("Connected to Kali.")

    # ========================================================
    # REMOTE COMMAND
    # ========================================================

    def run_remote_command(self, command):
        """
        Execute a command on Kali and return stdout.
        """

        if self.ssh is None:
            raise RuntimeError(
                "SSH connection has not been established."
            )

        stdin, stdout, stderr = self.ssh.exec_command(
            command
        )

        output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        if error.strip():
            logger.warning(
                error.strip()
            )

        return output

    # ========================================================
    # GET ADMIN TOKEN
    # ========================================================

    def get_admin_token(self):
        """
        Authenticate with Keycloak master realm.
        """

        logger.info(
            "Authenticating with Keycloak..."
        )

        command = f"""
curl -s -X POST \
"{self.config.keycloak_url}/realms/master/protocol/openid-connect/token" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode "username={self.config.keycloak_admin}" \
--data-urlencode "password={self.config.keycloak_password}" \
--data-urlencode "grant_type=password" \
--data-urlencode "client_id=admin-cli"
"""

        output = self.run_remote_command(
            command
        )

        try:
            response = json.loads(output)

        except json.JSONDecodeError:
            raise RuntimeError(
                "Invalid response received from Keycloak authentication."
            )

        if "access_token" not in response:
            raise RuntimeError(
                f"Keycloak authentication failed: {response}"
            )

        logger.info(
            "Keycloak authentication successful."
        )

        return response["access_token"]

    # ========================================================
    # GET USERS
    # ========================================================

    def get_users(self, token):
        """
        Retrieve users from the CyberFinGuard realm.
        """

        logger.info(
            "Retrieving Keycloak users..."
        )

        command = f"""
curl -s \
"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users?max=1000" \
-H "Authorization: Bearer {token}"
"""

        output = self.run_remote_command(
            command
        )

        try:
            users = json.loads(output)

        except json.JSONDecodeError:
            raise RuntimeError(
                "Invalid response received while retrieving users."
            )

        if not isinstance(users, list):
            raise RuntimeError(
                f"Failed to retrieve users: {users}"
            )

        logger.info(
            f"Retrieved {len(users)} Keycloak users."
        )

        return users

    # ========================================================
    # GET USER ROLES
    # ========================================================

    def get_user_roles(self, token, user_id):
        """
        Retrieve realm-level roles for a user.
        """

        command = f"""
curl -s \
"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users/{user_id}/role-mappings/realm" \
-H "Authorization: Bearer {token}"
"""

        output = self.run_remote_command(
            command
        )

        try:
            roles = json.loads(output)

        except json.JSONDecodeError:
            logger.warning(
                f"Invalid role response for user {user_id}"
            )
            return []

        if not isinstance(roles, list):
            logger.warning(
                f"Could not retrieve roles for user {user_id}"
            )
            return []

        return roles

    # ========================================================
    # GET USER GROUPS
    # ========================================================

    def get_user_groups(self, token, user_id):
        """
        Retrieve groups assigned to a user.
        """

        command = f"""
curl -s \
"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users/{user_id}/groups" \
-H "Authorization: Bearer {token}"
"""

        output = self.run_remote_command(
            command
        )

        try:
            groups = json.loads(output)

        except json.JSONDecodeError:
            logger.warning(
                f"Invalid group response for user {user_id}"
            )
            return []

        if not isinstance(groups, list):
            logger.warning(
                f"Could not retrieve groups for user {user_id}"
            )
            return []

        return groups

    # ========================================================
    # GET USER CLIENT ACCESS
    # ========================================================

    def get_user_clients(self, token, user_id):
        """
        Retrieve client/application role mappings.

        Some Keycloak versions/configurations may return
        HTTP 404 for this endpoint. That is handled safely.
        """

        command = f"""
curl -s \
"{self.config.keycloak_url}/admin/realms/{self.config.keycloak_realm}/users/{user_id}/role-mappings/clients" \
-H "Authorization: Bearer {token}"
"""

        output = self.run_remote_command(
            command
        )

        try:
            client_roles = json.loads(output)

        except json.JSONDecodeError:
            logger.warning(
                f"Invalid client access response for user {user_id}"
            )
            return []

        if (
            isinstance(client_roles, dict)
            and "error" in client_roles
        ):
            logger.warning(
                f"Could not retrieve client access for "
                f"user {user_id}: {client_roles}"
            )
            return []

        if not isinstance(client_roles, dict):
            logger.warning(
                f"Unexpected client access response for "
                f"user {user_id}"
            )
            return []

        clients = []

        for client_id, roles in client_roles.items():

            if not isinstance(roles, list):
                continue

            client_data = {
                "client_id": client_id,
                "roles": []
            }

            for role in roles:

                if not isinstance(role, dict):
                    continue

                client_data["roles"].append(
                    {
                        "id": role.get("id"),
                        "name": role.get("name"),
                        "description": role.get(
                            "description"
                        )
                    }
                )

            clients.append(
                client_data
            )

        return clients

    # ========================================================
    # GET AUTHENTICATION EVENTS
    # ========================================================

    def get_authentication_events(
        self,
        token,
        user_id=None,
        max_events=100
    ):
        """
        Retrieve Keycloak user authentication events.

        Events can include:
            LOGIN
            LOGIN_ERROR
            LOGOUT
            REGISTER
            CODE_TO_TOKEN
            REFRESH_TOKEN

        If user_id is supplied, events are filtered for that user.
        """

        logger.info(
            "Retrieving Keycloak authentication events..."
        )

        url = (
            f"{self.config.keycloak_url}"
            f"/admin/realms/"
            f"{self.config.keycloak_realm}"
            f"/events"
        )

        if user_id:
            url += (
                f"?user={user_id}"
                f"&first=0"
                f"&max={max_events}"
            )
        else:
            url += (
                f"?first=0"
                f"&max={max_events}"
            )

        command = f"""
curl -s \
"{url}" \
-H "Authorization: Bearer {token}"
"""

        output = self.run_remote_command(
            command
        )

        try:
            events = json.loads(output)

        except json.JSONDecodeError:
            logger.warning(
                "Invalid authentication events response."
            )
            return []

        if not isinstance(events, list):

            logger.warning(
                f"Could not retrieve authentication events: "
                f"{events}"
            )

            return []

        logger.info(
            f"Retrieved {len(events)} authentication event(s)."
        )

        return events

    # ========================================================
    # NORMALIZE AUTHENTICATION EVENT
    # ========================================================

    def normalize_event(self, event):
        """
        Convert a raw Keycloak event into a normalized
        CyberFinGuard IAM event structure.
        """

        if not isinstance(event, dict):
            return None

        details = event.get(
            "details",
            {}
        )

        if not isinstance(details, dict):
            details = {}

        return {
            "time": event.get(
                "time"
            ),

            "type": event.get(
                "type"
            ),

            "realm_id": event.get(
                "realmId"
            ),

            "client_id": event.get(
                "clientId"
            ),

            "user_id": event.get(
                "userId"
            ),

            "session_id": event.get(
                "sessionId"
            ),

            "ip_address": event.get(
                "ipAddress"
            ),

            "details": details
        }

    # ========================================================
    # COLLECT ALL KEYCLOAK DATA
    # ========================================================

    def collect(self):
        """
        Collect users, IAM context and authentication events.
        """

        # ----------------------------------------------------
        # Authenticate
        # ----------------------------------------------------

        token = self.get_admin_token()

        # ----------------------------------------------------
        # Retrieve users
        # ----------------------------------------------------

        users = self.get_users(
            token
        )

        enriched_users = []

        # ----------------------------------------------------
        # Process users
        # ----------------------------------------------------

        for user in users:

            user_id = user.get(
                "id"
            )

            username = user.get(
                "username"
            )

            logger.info(
                f"Collecting IAM context for: {username}"
            )

            # ------------------------------------------------
            # Roles
            # ------------------------------------------------

            roles = self.get_user_roles(
                token,
                user_id
            )

            normalized_roles = []

            for role in roles:

                if not isinstance(role, dict):
                    continue

                normalized_roles.append(
                    {
                        "id": role.get("id"),
                        "name": role.get("name"),
                        "description": role.get(
                            "description"
                        )
                    }
                )

            # ------------------------------------------------
            # Groups
            # ------------------------------------------------

            groups = self.get_user_groups(
                token,
                user_id
            )

            normalized_groups = []

            for group in groups:

                if not isinstance(group, dict):
                    continue

                normalized_groups.append(
                    {
                        "id": group.get("id"),
                        "name": group.get("name"),
                        "path": group.get("path")
                    }
                )

            # ------------------------------------------------
            # Client access
            # ------------------------------------------------

            clients = self.get_user_clients(
                token,
                user_id
            )

            # ------------------------------------------------
            # Authentication events for this user
            # ------------------------------------------------

            raw_events = self.get_authentication_events(
                token,
                user_id=user_id,
                max_events=100
            )

            normalized_events = []

            for event in raw_events:

                normalized_event = (
                    self.normalize_event(
                        event
                    )
                )

                if normalized_event is not None:
                    normalized_events.append(
                        normalized_event
                    )

            # ------------------------------------------------
            # Create normalized user object
            # ------------------------------------------------

            enriched_user = {
                "id": user_id,

                "username": username,

                "first_name": user.get(
                    "firstName"
                ),

                "last_name": user.get(
                    "lastName"
                ),

                "email": user.get(
                    "email"
                ),

                "email_verified": user.get(
                    "emailVerified",
                    False
                ),

                "enabled": user.get(
                    "enabled",
                    False
                ),

                "mfa_enabled": user.get(
                    "totp",
                    False
                ),

                "roles": normalized_roles,

                "groups": normalized_groups,

                "clients": clients,

                "authentication_events": normalized_events
            }

            enriched_users.append(
                enriched_user
            )

        return {
            "realm": self.config.keycloak_realm,
            "users": enriched_users
        }

    # ========================================================
    # CLOSE CONNECTION
    # ========================================================

    def close(self):
        """
        Close SSH connection.
        """

        if self.ssh is not None:

            self.ssh.close()

            logger.info(
                "SSH connection closed."
            )


# ============================================================
# MAIN
# ============================================================

def main():
    """
    Main program.
    """

    ingestor = KeycloakIngestor()

    try:

        # ----------------------------------------------------
        # Connect
        # ----------------------------------------------------

        ingestor.connect_ssh()

        # ----------------------------------------------------
        # Collect
        # ----------------------------------------------------

        data = ingestor.collect()

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        print()
        print(
            "Keycloak ingestion successful."
        )

        print(
            f"Realm: {data['realm']}"
        )

        print(
            f"Users collected: "
            f"{len(data['users'])}"
        )

        # ----------------------------------------------------
        # Display users
        # ----------------------------------------------------

        for user in data["users"]:

            print()
            print(
                f"User: {user['username']}"
            )

            print(
                f"  User ID: {user['id']}"
            )

            print(
                f"  Email: {user['email']}"
            )

            print(
                f"  Enabled: {user['enabled']}"
            )

            print(
                f"  Email verified: "
                f"{user['email_verified']}"
            )

            print(
                f"  MFA enabled: "
                f"{user['mfa_enabled']}"
            )

            # ------------------------------------------------
            # Roles
            # ------------------------------------------------

            role_names = [
                role["name"]
                for role in user["roles"]
                if role.get("name")
            ]

            roles_text = (
                ", ".join(role_names)
                if role_names
                else "None"
            )

            print(
                f"  Roles: {roles_text}"
            )

            # ------------------------------------------------
            # Groups
            # ------------------------------------------------

            group_names = [
                group["name"]
                for group in user["groups"]
                if group.get("name")
            ]

            groups_text = (
                ", ".join(group_names)
                if group_names
                else "None"
            )

            print(
                f"  Groups: {groups_text}"
            )

            # ------------------------------------------------
            # Client access
            # ------------------------------------------------

            print(
                f"  Client access: "
                f"{len(user['clients'])} client(s)"
            )

            for client in user["clients"]:

                client_id = client.get(
                    "client_id"
                )

                client_roles = [
                    role["name"]
                    for role in client.get(
                        "roles",
                        []
                    )
                    if role.get("name")
                ]

                client_roles_text = (
                    ", ".join(client_roles)
                    if client_roles
                    else "No roles"
                )

                print(
                    f"    - {client_id}: "
                    f"{client_roles_text}"
                )

            # ------------------------------------------------
            # Authentication events
            # ------------------------------------------------

            events = user.get(
                "authentication_events",
                []
            )

            print(
                f"  Authentication events: "
                f"{len(events)}"
            )

            # Display the latest 10 events
            # rather than flooding the terminal.

            for event in events[:10]:

                print(
                    f"    - "
                    f"{event.get('type')} | "
                    f"time={event.get('time')} | "
                    f"client={event.get('client_id')} | "
                    f"ip={event.get('ip_address')}"
                )

    except Exception as exc:

        logger.error(
            f"Keycloak ingestion failed: {exc}"
        )

    finally:

        ingestor.close()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()