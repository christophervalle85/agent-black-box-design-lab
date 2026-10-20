# Design Lab — Connected Story iteration

This document records the design strategy for the read-only v0.9 showcase in the **separate private design-lab repository**. These visual changes do not establish additional security guarantees.

## User problem addressed

The previous Precision Workbench displayed the same information in separate elements: a hero, case menu, a dark workbench, an inspector, a detached architecture area, and an evidence list. Although technically accurate, visitors had to assemble the causal story themselves.

The new design has one primary question per chapter:

1. **Follow a request.** What was asked, how was it evaluated, what happened, and what supports the statement?
2. **Understand the boundaries.** Which decisions come from the routed Node guard, human consent, native macOS worker, and local audit controls?
3. **Inspect the evidence.** Where are source documents and acceptance results, and what remains unproven?

The six cases are *alternative investigations* (native select), while steps inside each case are an *ordered explanation*. A persistent, short outcome and its limitation remain visible rather than being hidden behind a second UI.

## Source-backed design rationale

- [Nielsen Norman Group — Progressive Disclosure](https://www.nngroup.com/articles/progressive-disclosure/): show the essential decision first and retain deeper detail where needed. No fake metrics or generic dashboards.
- [Nielsen Norman Group — Information Scent](https://www.nngroup.com/articles/information-scent/): use explicit labels, such as "Read supporting documentation", and put source context with its claim.
- [U.S. Web Design System — Process List](https://designsystem.digital.gov/components/process-list/): use a numbered visual path for a genuinely sequential request evaluation, not for unrelated options.
- [GOV.UK — Step by step navigation](https://design-guide.publishing.service.gov.uk/frontend-templates/step-by-step-nav/): don't confuse a collection of choices with a linear journey.
- [W3C WAI — Disclosure](https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/): use native controls and clear semantics for optional details. This iteration primarily uses a native select and buttons.

These references motivate information architecture and interaction patterns; they do not certify the project's usability or visuals.

## Implementation decisions

- One consistent chapter rhythm and a single case narrative: **request → staged evaluation → outcome → evidence and caveat**.
- One prominent code excerpt per case. Do not represent the signed native diagnostic or audit fixture as an ordinary agent tool request.
- Source and limitations immediately follow the outcome in the same case surface.
- Technical metadata is supportive, not competing with the story.
- Simple native select for switching six different cases; native buttons for stepping through the reconstructed sequence.
- No live API calls, approval actions, audit mutations, external CDN dependencies, or arbitrary framework migrations.
- Original immutable scenario definitions and documented source URLs are unchanged.
- A specific disclaimer explains that the human-approval fixture does not contain note-body content.

## Acceptance / user comprehension checklist

Ask a first-time viewer, without coaching:

1. What did the agent request in the selected case?
2. Which component enforced the decision?
3. What happened, and did execution actually occur?
4. Is this a live session or a reconstruction?
5. What documentation supports this result, and what does it **not** prove?

Review if all five answers can be located without hunting across multiple dashboard cards.

## Browser quality checks (not yet completed)

- `PORT=4318 npm start` and visit `http://127.0.0.1:4318/showcase`.
- Compare first-screen composition at 1440×900, 1280×800, 768px, 390px, and 320px.
- Confirm header logo left inset, no horizontal overflow, readable stage buttons and proof copy.
- Use Safari keyboard-only case selection, all stage buttons, restart, browser Back, and deep links `?case=human-approval&step=3`.
- Verify reduced motion and readable contrast.
- Run local `npm test` and `node --check public/showcase.js`.

## Verification status

Static source checks pass, and a simulated DOM exercise covered all six fixtures, every stage, restart, and case cycling. GitHub Actions is presently reporting failures with zero executed job steps in the private design-lab repository; CI results are not available as a meaningful verification yet. No full browser screenshot review or local Node regression-suite run has been completed here. Keep the PR in draft.
