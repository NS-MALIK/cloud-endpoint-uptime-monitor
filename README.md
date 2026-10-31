# 🚀 Cloud Endpoint & Database Uptime Monitor

[![Cloud Endpoint Uptime Monitor](https://github.com/NS-MALIK/cloud-endpoint-uptime-monitor/actions/workflows/monitor.yml/badge.svg)](https://github.com/NS-MALIK/cloud-endpoint-uptime-monitor/actions/workflows/monitor.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, serverless infrastructure monitoring engine written in Python. It automatically performs multi-metric health checks across HTTP/HTTPS endpoints, PostgreSQL databases, and MongoDB clusters—evaluating response status, connection latency, and SSL certificate validity before dispatching instant alerts via webhooks and updating an audit log.

---

## 🛠️ Tech Stack & Architecture

* **Core Language:** Python 3.10 (`requests`, `psycopg2-binary`, `pymongo`, `ssl`, `socket`)
* **Automation Engine:** GitHub Actions (Cron runner executing every 30 minutes)
* **Alerting Engine:** Webhook Integration for Discord & Slack
* **Audit Persistence:** Automated commit step recording status checks to `incident_history.json`