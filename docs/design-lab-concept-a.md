# Design lab / Concept A — Precision Workbench

This is an experimental public-showcase frontend, **not an implementation of new security controls**. It replaces the original orbital hero and split sidebar/timeline with a compact introduction, a horizontally indexed set of investigations, a central request/decision workspace and a decision inspector.

## Goals

- Place the product mark at the left edge of the site header, with independent centered navigation and a right-aligned source link.
- Keep the first meaningful investigation near the top instead of burying it below decorative art.
- Make the request, causal stages, and evidence scope readable together.
- Give policy, human review, macOS diagnostic and audit cases different supporting context without inventing live metrics.
- Preserve all six v0.9 scenario fixtures and source references unmodified.
- Avoid adding runtime libraries, external fonts, network calls or permission-bearing UI to the showcase.

## Deliberate design choices

- System typography for performance, readable prose for explanations, monospace only for rules and payloads.
- A neutral document surface with a single dark code/decision canvas; no fake terminal chrome or radar graphics.
- CSS Grid for header/workspace architecture, intrinsic sizing, responsive horizontal case index and mobile vertical stages.
- Semantic native buttons, clear `aria-pressed` / `aria-current` semantics, visible focus, reduced-motion rules.
- A new same-origin SVG mark served through the existing restricted static-route map.

## Source and security boundaries

The public page reads only the bundled `showcase-scenarios.mjs`. It does **not** call local APIs. The case chooser and stepper update DOM text, an optional shareable query string, and nothing else. The native scenario references a separately signed worker-source diagnostic; the installed native worker was not freshly tested by this design change. The Node parent is not sandboxed.

Docs and evidence links intentionally target the **original** project's accepted documentation, not invented evidence in this design repository.

## Review checklist (not yet visually signed off)

1. `npm test` and `node --check public/showcase.js` / `node --check src/server.mjs`
2. `PORT=4318 npm start` and open `http://127.0.0.1:4318/showcase`
3. Capture 1440×900, 1280×800, 768px, 390px, and 320px screenshots in Safari/Chromium.
4. Confirm the wordmark is flush with the header's intentional ~20px content gutter, nav stays usable and nothing causes page-wide horizontal overflow.
5. Choose each of six investigations, navigate every stage by keyboard, restart, use browser Back and a shared `?case=...&step=...` link.
6. Check no case interaction mutates files, requests a model, or issues an approval.
7. Verify macOS and audit limitations remain readable at all widths.
8. Visually critique information density, contrast, typographic hierarchy and first-viewport composition before selecting this concept for production.

This experimental branch is not a substitute for hands-on visual review.
