# AI Agent Instructions

When writing code that handles user input, authentication, sessions, permissions, secrets, databases, files, network calls, LLM prompts/tools, or raw memory:
1. Read `SKILL.md` and apply matching design groups and templates (`templates/<language>.md`).
2. When architecting systems, review `checks/secure-by-design.md`, `checks/memory-safety.md`, `checks/cryptography.md`, `checks/iot-security.md`, `checks/deployment-safety.md`, or `checks/sbom.md`.
3. When building AI/LLM workflows or RAG pipelines, review `checks/llm-top10.md`.
4. After writing code, run: `node hooks/scan.js --staged`
5. Before declaring completion, run the Done Gate:
   `node hooks/summary.js && node hooks/audit.js && node hooks/gate.js --check`
6. `gate.js --check` exits 2 until you answer the four questions the scanner
   cannot check — ownership, authorization, taint, failure-direction. Record each
   with `node hooks/gate.js --answer <question> "<what enforces it>"`. "N/A" is
   valid; "yes" is rejected. A clean scan is not a pass on its own.

