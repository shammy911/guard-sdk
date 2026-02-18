# @shammy911/guard-sdk

A tiny client for the **Guard API** — a rate-limiting + abuse protection service.

Use it to ask Guard:

> “Should I allow this request to this route right now?”

Guard replies:

- `{ allowed: true }`
- `{ allowed: false, reason?: ... }`

This SDK is designed for **server-side usage** (recommended), so your API key stays private.

---

## Install

```bash
npm i @shammy911/guard-sdk
```
