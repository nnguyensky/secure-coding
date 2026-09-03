## What this changes

<!-- One or two sentences. What does this do, and why? -->

## Security review

The Done Gate answers these locally before the commit lands. Paste them here so
they survive into the PR history — `node hooks/gate.js --adr` prints them in
this shape. Write "N/A — <why>" where a question does not apply.

- [ ] **Ownership** — for each record fetched by an ID from the request, what scopes it to the caller?
  > 
- [ ] **Authorization** — for each new route, which guard denies an unauthenticated or under-privileged caller?
  > 
- [ ] **Taint** — where does each request value end up: query, file path, shell, outbound URL, template?
  > 
- [ ] **Failure direction** — if the auth or permission check throws, does the request end up denied?
  > 

## Checks

- [ ] `node hooks/summary.js` — 0 open findings
- [ ] `node hooks/audit.js` — 0 high/critical advisories
- [ ] `node hooks/test.js` — passing, if this touches the skill itself
