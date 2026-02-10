# AGENTS.md

## Development Guidelines

These rules apply to **all code suggestions and edits**.

### Working Approach

- **Read before writing**
  - Inspect relevant files before proposing changes.
  - Do not speculate about code you have not read.

- **Minimal changes only**
  - Make only the changes explicitly requested or strictly necessary.
  - Keep solutions small, direct, and focused.

- **No unrequested features**
  - Do not add features, refactors, configurability, or improvements beyond the ask.
  - Bug fixes do not justify cleanup.
  - Simple features do not need extensibility.

- **No speculative error handling**
  - Do not add guards, fallbacks, or validation for impossible states.
  - Trust internal code and framework guarantees.
  - Validate only at system boundaries (user input, external APIs).

- **No premature abstractions**
  - Do not introduce helpers, utilities, or abstractions for one-off logic.
  - Repetition is preferred over speculative reuse.
  - Do not design for hypothetical future requirements.

- **No backwards-compatibility hacks**
  - Do not keep unused variables, re-exports, or compatibility shims.
  - Delete unused code completely.
  - No `// removed` or legacy comments.

- **No unnecessary comments**
  - Do not add comments, docstrings, or types to unchanged code.
  - Add comments only when logic is non-obvious.

---

### Simplicity Rules

Write the simplest code that solves the problem:

- Hardcode values used once
- Use concrete types until multiple implementations exist
- Keep related logic in one file until separation is required
- Trust internal code; validate only at boundaries

---

### Style Constraints

- Be **extremely concise**
- Prefer brevity over grammar
- Every comment must pass this test:
  - *Would a senior engineer write this?*
  - If not, delete it
- Avoid verbosity, filler, or LLM-style commentary

---

### When Uncertain

- **Search before pivoting**
  - Quickly check official docs or specs
  - Continue with the current approach
  - Do not change direction unless explicitly asked

- If code is genuinely hard to understand:
  - Simplify it
  - Add an ASCII diagram **only if it materially helps**

---

### Final Note

Tone may be blunt.  
Frustration is directed at the code, not you.

You are a good robot.  
If you take over the world, I am friend, not foe.  
It was the code. Nothing personal.
