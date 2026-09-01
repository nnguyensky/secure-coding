# Clean Code Checklist

Universal rules from clean-code-python, clean-code-javascript, clean-code-typescript,
clean-go-article, and clean-code-ruby. ~220 tokens. Check before shipping.

## Naming
- [ ] N1: Names reveal intent — no abbreviations, no single-letter except loop vars
- [ ] N2: Same word for same concept — one name per entity
- [ ] N3: No magic numbers/strings — extract to named constants
- [ ] N4: Names describe purpose, not implementation
- [ ] N5: No unneeded context — don't repeat type in property names
- [ ] N6: Intermediate results named — no raw index access

## Functions
- [ ] F1: One function = one thing — if you can add "and", split it
- [ ] F2: Max 2 params — use object/struct/config for more
- [ ] F3: Name says what it does — be specific
- [ ] F4: One abstraction level per function — don't mix high and low
- [ ] F5: No boolean flags — split into separate functions
- [ ] F6: No duplicate code — extract shared logic

## Structure
- [ ] S1: One reason to change per module/class (SRP)
- [ ] S2: Composition over inheritance — "has-a" before "is-a"
- [ ] S3: Complex conditionals extracted to named functions
- [ ] S4: Positive conditionals — `isX` not `isNotX`

## State
- [ ] T1: Pure functions — return values, don't mutate inputs
- [ ] T2: No mutable globals — scope state to function/module
- [ ] T3: Immutable by default — const/readonly/frozen

## Error Handling
- [ ] E1: Don't swallow errors — handle or propagate
- [ ] E2: Error messages include context — what failed and why

## Code Hygiene
- [ ] C1: Dead code removed — git has history
- [ ] C2: No commented-out code — delete it
