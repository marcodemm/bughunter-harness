---
name: prototype-pollution
description: |
  Server-side and client-side prototype pollution — payload variants,
  detection sinks, PoC scaffolding for Node/Express/Lodash targets.
severity_hint: high

# Which core agents may load this technique into their system prompt.
# Use ["*"] to allow every agent. Default (omitted) = every agent.
loaded_by_agents:
  - web_vuln
  - api_fuzzer

# The technique is injected into the agent prompt ONLY when the current
# target context matches all `applies_when` rules. Both keys are optional;
# if omitted the technique is always applicable.
applies_when:
  # At least ONE of these must appear in state.detected_techs
  detected_techs:
    - nodejs
    - node.js
    - express
    - lodash
    - koa
    - hapi
    - jquery      # DOM-based variant
  # At least ONE of these fnmatch globs must match a discovered endpoint
  endpoints_match:
    - "**/api/**"
    - "**/graphql*"
    - "**/config*"
---

# Prototype Pollution — how to test

Server-side prototype pollution lets an attacker set arbitrary properties
on `Object.prototype` via user-controlled JSON merging. Once polluted, any
downstream code that reads a property with a `if (obj.isAdmin)`-style check
returns the injected value regardless of the actual object.

## Sources (where the pollution enters)

- `JSON.parse` on user input + shallow merge (`Object.assign`, `_.merge`,
  `_.mergeWith`, `_.defaultsDeep`, `hoek.merge`).
- Query string parsers with `qs` in "extended" mode (Express default):
  `?a[__proto__][polluted]=yes` becomes `{ a: { __proto__: { polluted: yes } } }`.
- HTTP body parsers: `body-parser` `extended: true`, `express-fileupload`.

## Sinks (where the pollution matters)

- Auth: `if (user.isAdmin)` short-circuits — grants admin.
- Command injection: libraries reading `options.shell` from prototype.
- SSRF: URL parsers reading `options.host`.
- Denial of service: setting `.toString` to a non-function crashes stringify.

## Payload — quickest test

```
GET /any/endpoint?__proto__[polluted]=yes
GET /any/endpoint?constructor[prototype][polluted]=yes
POST /any/endpoint  Content-Type: application/json
Body: {"__proto__": {"polluted": "yes"}}
```

Then GET any UNRELATED endpoint and look for a JSON response that includes
`"polluted": "yes"` — proves the property was set on `Object.prototype` and
is now visible everywhere.

## PoC scaffolding for the report

1. Baseline: GET `/api/status` → note the shape of the response.
2. Pollute: POST `/api/user/prefs` with `{"__proto__":{"leaked":"proof"}}`.
3. Confirm: GET `/api/status` again → `"leaked":"proof"` appears where it
   was NOT before. This is the demonstrable impact for the triager.
4. Escalate (only if trivially safe):
   - Look for `if (options.something)` reads across the app JS.
   - `__proto__[isAdmin]=true` and re-hit any authorization endpoint.

## Impact classification

- HIGH: pollution + demonstrable authz bypass or SSRF/RCE primitive.
- MEDIUM: pollution + XSS in a downstream template (client-side variant).
- LOW: pollution proven but no sink reachable from user data (audit finding).

## Fix guidance

- Freeze the prototype at startup: `Object.freeze(Object.prototype)`.
- Use `Object.create(null)` for parsed JSON containers.
- Upgrade `lodash` to ≥ 4.17.21, `jquery` to ≥ 3.5.0, `hoek` to ≥ 6.1.3.
- Reject property names in `__proto__`, `constructor`, `prototype` at the
  parser layer.
