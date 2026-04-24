# agentic-ai-mcp-security-labs
Note: it’s community labs, not official OWASP.

# Agentic AI + MCP Security Labs (OWASP MCP Top 10 Aligned)

This repository contains hands-on, runnable labs demonstrating **security risks and mitigations for MCP-based agentic AI deployments**, aligned to the **OWASP MCP Top 10** threat themes (with special focus on **MCP-01: Token/Credential Exposure & Tool Authorization Abuse**).

The labs are designed for:
- Enterprise-grade agentic AI deployments (ITSM/Service Desk, internal tools, multi-tool agents)
- Security research and academic thesis work (threat modeling, evaluation, reproducible experiments)
- Demonstrating secure design patterns: **token-less execution**, **capability-based security**, and **safe delegation flow**

> ⚠️ Disclaimer: This repository is an independent educational lab project inspired by OWASP risk themes. It is not an official OWASP project.

---

## 🎯 What You Will Learn

- Why **MCP-01** happens: secrets and execution authority crossing into LLM reasoning context
- How to implement **Token-less Execution**: isolate enterprise tokens within the tool server boundary
- How to implement **Capability-Based Security**: enforce least privilege for agent tool usage
- How to design a **Safe Delegation Flow**: delegate *authority* without exposing *identity tokens*
- How to integrate a real local LLM with **Ollama** for realistic agent behavior
- How prompt injection can lead to tool misuse, and how to prevent it using architecture

---

## 🧱 Repository Structure
