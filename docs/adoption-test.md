# The adoption test

One bounded question, asked once: **does anyone come back to this?**

Astra's SF-11 set the shape — a small experiment, a month at most, no new
product built on top of it while it runs. This file is the protocol, so the
answer is recorded rather than remembered.

## What is being tested

That a person who installs this server uses it a second time, on a different
day, without being asked to. Not downloads, not stars, not "interesting".

## What it is not

- **No vault credential.** The reason is in the README and has not changed: the
  only token the vault API accepts opens everything, and a scoped metadata-only
  key does not exist yet. If this test produces demand for vault automation,
  that demand is an input to designing the scoped key, not permission to ship
  the broad one.
- **No AI chat product.** The server stays a local file manager.
- **No second experiment while this one runs.** One question at a time.

## Before it starts

1. `npm run demo` — the synthetic run, so the claims can be shown rather than
   described.
2. `npm publish` (founder step; `npm whoami` must succeed first).
3. Post it once, where people who manage their own files already are. The
   README's *What this cannot do* section is the honest part; lead with it.

## The five conversations

Ask the same five questions, in this order, and write the answers down verbatim.

1. What did you point it at? (Which folders, and why those.)
2. What did you ask it for the first time?
3. What did it get wrong, or refuse, that you expected it to do?
4. Did you use it again? When, and what for?
5. Is there anything you wanted it to do with your ShieldFive vault?

Question 5 is the one to record most carefully and act on least: it is the input
to a future scoped-key design, and it is the question most likely to tempt an
unsafe shortcut.

## The rule

| Outcome | Then |
|---|---|
| 5 people can describe what it does, and 3 return unprompted | Keep it, and pick the single most-repeated blocker to fix |
| Fewer than 3 return | Maintenance only. Leave it published, stop investing, and say so in the plan |
| Any vault-automation request | Record it here verbatim. Do not design a credential during this test |

## Results

| Date | Person | Roots used | First ask | What it got wrong | Returned? | Vault wish |
|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — |

Fill this table as the conversations happen, and carry the verdict into
`shieldfive/web` `docs/gtm/profit-plan-2026-09.md` (row 12) when the month is up.
