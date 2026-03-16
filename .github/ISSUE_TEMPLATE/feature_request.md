---
name: Feature Request
about: Suggest a new feature (security-first evaluation)
title: '[FEATURE] '
labels: 'enhancement, triage'
assignees: ''
---

<!--
╔════════════════════════════════════════════════════════════════╗
║  MINIMUM PRINCIPLE: Only essential features are accepted.      ║
║  Features that increase attack surface WILL BE REJECTED.       ║
╚════════════════════════════════════════════════════════════════╝
-->

## Pre-Submission Checklist

- [ ] This feature is absolutely necessary
- [ ] This cannot be achieved with existing functionality
- [ ] This follows the security-first principle
- [ ] This doesn't increase attack surface

## Feature Description

A clear and concise description of the feature.

## Use Case

Why is this feature needed? What problem does it solve?

## Security Impact Assessment

| Question | Answer |
|----------|--------|
| Does this increase attack surface? | [Yes/No/Unknown] |
| Does this require new dependencies? | [Yes/No] - List them: |
| Does this handle sensitive data? | [Yes/No] |
| Can this feature be misused? | [Yes/No/Unknown] - How: |
| Does this bypass any security controls? | [Yes/No] |

## Proposed Implementation

How might this be implemented? (Optional, but helpful)

## Alternatives Considered

What alternatives have you considered?

## Additional Context

Any other relevant information.
