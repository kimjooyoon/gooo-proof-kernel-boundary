# Contribution contract

Ownership receipt: `owner_thread_id=01a0558a-0081-78a1-81d3-cabec152c16f`,
`scope=gooo-proof-kernel-boundary`, `shared-workspace=single-writer`.

This repository has an explicit trust boundary.

- `internal/kernel` is the trusted proof kernel. Its verdict vocabulary,
  `REFUTED > UNKNOWN > CLOSED` precedence, fixed denominator, SHA-256 digest
  identity, and authority ceiling are immutable policy.
- `internal/evaluator/generated.go` is untrusted generated code. It may submit
  observations to the kernel but cannot redefine kernel verdicts, precedence,
  denominator, digest verification, or authority operations.
- `.gooo` is the source authority for exactly 12 semantic activities. The
  semantic IR and generated evaluator are derived views bound to that source.
- A trusted-kernel change requires an immutable parent release and digest plus a
  separate human authorization receipt. Missing proof is fail-closed
  `UNKNOWN`; self-trust or any attempted override is `REFUTED`.
- `UNKNOWN` always carries `stage`, `step`, `reason`, `unknown_class`,
  `next_operation`, and `blocked_by`. Direct missing and dependency blocked are
  different classes.
- The evaluator writes only to a caller-owned output directory. It never edits
  the source repository, runs another repository's CI, or treats trusted LOC
  size as an improvement claim.

Go build, test, race, vet, and formatting validation are CI-only operations.
