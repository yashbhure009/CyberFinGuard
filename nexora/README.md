# Nexora — Vulnerable Fictional Company Website


## Purpose

Nexora is the synthetic company that your judges interact with first. Its running
web application contains deliberately weak/legacy patterns and technology fingerprints
for a controlled security assessment. The broader enterprise inventory represents
the remaining shortlisted technologies that are not browser-facing.

The exact shortlist is limited to the following 30 CVEs:

- CVE-2024-27198 — TeamCity — DevOps / CI Server
- CVE-2021-26855 — Microsoft Exchange — Email Server
- CVE-2021-34473 — Microsoft Exchange — Email Server
- CVE-2021-27065 — Microsoft Exchange — Email Server
- CVE-2019-0604 — Microsoft SharePoint — Collaboration Server
- CVE-2021-22893 — Pulse Connect Secure — VPN Gateway
- CVE-2018-0296 — Cisco ASA — Network Firewall
- CVE-2024-37079 — VMware vCenter — Virtualization Server
- CVE-2025-14847 — MongoDB — Customer Database
- CVE-2023-27532 — Veeam Backup & Replication — Backup Server
- CVE-2018-16763 — Fuel CMS — Public Web/CMS
- CVE-2019-9053 — CMS Made Simple — Public Web/CMS
- CVE-2025-64459 — Django — Application Server
- CVE-2017-1000499 — phpMyAdmin — Database Admin
- CVE-2024-21514 — OpenCart — E-commerce
- CVE-2015-1398 — Magento — E-commerce
- CVE-2020-15867 — Gogs — Git Server
- CVE-2021-41303 — Apache Shiro — Application Authentication
- CVE-2023-43622 — Apache HTTP Server — Public Web Server
- CVE-2025-1098 — ingress-nginx — Kubernetes Ingress
- CVE-2019-1215 — Microsoft Windows — Windows Server
- CVE-2024-21345 — Windows Server — Windows Server
- CVE-2021-26411 — Internet Explorer/Windows — Employee Workstation
- CVE-2023-44466 — Linux kernel — Linux Server
- CVE-2021-32675 — Redis — Cache Server
- CVE-2020-27751 — ImageMagick — File Processing
- CVE-2023-28341 — ManageEngine Applications Manager — Monitoring
- CVE-2021-26929 — Horde Webmail — Webmail
- CVE-2020-25706 — Cacti — Monitoring
- CVE-2023-0830 — EasyNAS — Storage

## What is actually running

The web application has:
- public corporate pages
- e-commerce/product functionality
- customer login
- internal admin surface
- APIs
- file-processing surface
- database-backed application
- scanner-friendly technology/lab fingerprint endpoints

The application intentionally includes safe demonstration weaknesses such as:
- legacy authentication handling
- insecure direct object access pattern
- legacy query construction in a controlled API
- exposed internal/admin surfaces
- file-processing input surface

These are **not exploit implementations**. No weaponized payloads are included.

## Important CVE distinction

Not all 30 CVEs are vulnerabilities in browser HTML itself. Several are vulnerabilities
in server/infrastructure products such as Exchange, Cisco ASA, VMware vCenter, Veeam,
EasyNAS and Windows. Those are represented as components of Nexora's enterprise
environment and asset inventory.

For a real scanner-backed SIH deployment, these internal assets should be deployed as
isolated, version-pinned vulnerable lab VMs/containers. This package keeps that layer
descriptive so it does not ship weaponized exploit infrastructure.

## Run locally

PowerShell:

    cd app
    python -m pip install -r requirements.txt
    python -m uvicorn app:app --reload --port 8200

Open:

    http://127.0.0.1:8200

Useful demo surfaces:

    /solutions
    /login
    /admin
    /api/products
    /api/search?q=cloud
    /api/profile?email=demo@nexora.local
    /uploads
    /.well-known/nexora-lab
    /lab/asset-inventory
    /lab/cve-scope

## Docker

Dockerfile and docker-compose.yml are included for your Git/deployment workflow.
Docker is NOT required for local development.
