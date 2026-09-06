cyberFinguard
## Database Schema

The platform uses PostgreSQL to store and manage cybersecurity data required for
continuous cyber risk quantification and security investment optimization.

### Database Architecture

```text
                         ┌──────────────────┐
                         │      ASSETS      │
                         │ Master Inventory │
                         └────────┬─────────┘
                                  │
                  ┌───────────────┼───────────────┐
                  │               │               │
                  ▼               ▼               │
          ┌──────────────┐ ┌────────────────┐      │
          │   FINDINGS   │ │ ASSET_CONTROLS │      │
          │              │ │                │      │
          │ CVE / CVSS   │ │ MFA            │      │
          │ EPSS / KEV   │ │ WAF            │      │
          │ Severity     │ │ EDR            │      │
          │ Source       │ │ Firewall       │      │
          └──────┬───────┘ │ Encryption     │      │
                 │         │ Backup         │      │
                 │         └────────────────┘      │
                 ▼                                 │
          ┌──────────────┐                         │
          │ RISK_SCORES  │                         │
          │              │                         │
          │ SLE          │                         │
          │ ARO          │                         │
          │ ALE          │                         │
          │ Likelihood   │                         │
          │ Impact       │                         │
          └──────┬───────┘                         │
                 │                                 │
                 ▼                                 │
     ┌──────────────────────────────┐              │
     │ INVESTMENT_RECOMMENDATIONS   │◄─────────────┘
     │                              │
     │ Investment Cost              │
     │ Risk Reduction               │
     │ ROI                          │
     │ Priority                     │
     └──────────────────────────────┘
```

### Tables

| Table | Description |
|---|---|
| `assets` | Master inventory containing organizational assets and their business context |
| `findings` | Security findings collected from security tools such as Wazuh, OpenVAS, Prowler, ZAP and Keycloak |
| `asset_controls` | Security control status associated with each asset |
| `risk_scores` | Calculated technical and financial risk metrics for assets and findings |
| `investment_recommendations` | Recommended security investments, expected risk reduction, ROI and priority |

### Key Relationships

- Each **asset** can have multiple security **findings**.
- Each **asset** has an associated **security control status**.
- Findings and assets are used to calculate **risk scores**.
- Risk analysis feeds into **investment recommendations**.
- Original security-tool output is preserved in the `raw_data` JSONB field.

### Database Schema File

The complete PostgreSQL schema is available at:

[`database/schema.sql`](database/schema.sql)