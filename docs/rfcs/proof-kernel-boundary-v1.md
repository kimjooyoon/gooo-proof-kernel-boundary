# Proof kernel boundary v1

## Purpose

Self-improvement is allowed to change policy, candidate selection, and
evaluator code. It is not allowed to change the proof kernel while using the
same kernel to approve that change. This repository makes that boundary
explicit.

## Trusted side

`internal/kernel` is the trusted side. Its small API owns:

1. `CLOSED`, `UNKNOWN`, and `REFUTED`;
2. the precedence `REFUTED > UNKNOWN > CLOSED`;
3. the exact fixed denominator of 12;
4. the SHA-256 digest verifier identity;
5. the authority ceiling of immutable-input reads and caller-owned report
   writes;
6. the six-field UNKNOWN tuple; and
7. parent-kernel change authorization.

The kernel rejects any non-empty override for its verdict, precedence,
denominator, digest verifier, or authority ceiling. A self-trust flag is also
an immediate `REFUTED` result. These checks happen before a candidate status is
considered.

## Untrusted side

`internal/evaluator/generated.go` is a generated, untrusted adapter. It can
submit a candidate observation to `kernel.Verify`; it cannot supply an
alternative implementation of the kernel contract. The `.gooo` source names
the 12 activities. CI compiles that source to semantic IR, verifies the IR's
source digest, and then runs the generated adapter to produce the report.

## Trusted-kernel changes

A trusted-kernel change is a two-input operation:

- an immutable parent release with an exact release and asset digest; and
- a separate human authorization receipt naming the same parent digest and the
  `CHANGE_TRUSTED_KERNEL` operation.

If either input is missing, the kernel emits `UNKNOWN` with all six fields. A
malformed or mismatched release/receipt is `REFUTED`. No candidate can make a
kernel change succeed by setting `self_trusted` or by changing the verdict.

## Evidence and non-claims

The 12 controlled cases cover normal operation, direct missing evidence,
dependency blocking, missing parent proof, every protected override, and
self-trust. CI reports exact normal/unknown/refuted counts. The report does
not use a score or percentage. Trusted LOC is an inventory observation only;
without an exact comparable before/after pair, any improvement claim is
`UNKNOWN` with `DIRECT_MISSING` and a next operation to provide that pair.

The evaluator writes only to a caller-owned temporary directory. The source
repository remains unchanged during conformance. Optional external release
locks are read as immutable identities only. No other repository's branch, PR,
or CI is a required gate.
