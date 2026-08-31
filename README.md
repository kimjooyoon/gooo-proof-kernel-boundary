# gooo-proof-kernel-boundary

`gooo-proof-kernel-boundary` demonstrates a small trusted proof kernel beneath
a replaceable, generated evaluator. The evaluator can evolve policy and
candidate logic, but it cannot silently become the judge.

The flow is explicit:

```text
.gooo source → semantic IR → generated untrusted evaluator
                              → trusted proof kernel → human report
```

The trusted kernel owns the verdict vocabulary, `REFUTED > UNKNOWN > CLOSED`
precedence, exact 12-cell boundary, SHA-256 digest verification, and the
authority ceiling. An evaluator that supplies a verdict, precedence,
denominator, digest-verifier, or authority-ceiling override is `REFUTED`.
Self-trust is also `REFUTED`.

If a candidate proposes changing the trusted kernel, it must provide both an
immutable parent-kernel release identity/digest and a separate human
authorization receipt. Missing proof is an explicit six-field `UNKNOWN`, never
an implicit success.

## Scenarios and output

CI evaluates exactly 12 controlled scenarios: 3 normal, 3 `UNKNOWN`, and 6
`REFUTED`. The cases include direct missing evidence, dependency blocking,
unauthorized kernel change, kernel verdict override, precedence override,
denominator override, digest-verifier override, authority-ceiling override,
and self-trust.

The uploaded machine artifact and human summary contain exact integer counts,
trusted/generated/Gooo file and line counts, kernel API surface count, allowed
and denied authority operations, build/test/conformance `wall_ms` and
`peak_rss_kib`, and artifact file/byte counts. It does not calculate a score or
percentage. A smaller trusted implementation is not treated as an improvement;
without an exact comparable before/after pair, improvement remains `UNKNOWN`.

`repository_writes`, `local_test_executions`, and
`cross_project_required_gates` are explicit `0` fields. Root `README.md` is
excluded from the physical inventory as a documentation exception. Optional
external inputs are immutable release locks only; another repository's branch,
PR, or CI is never a required gate.

## Verification boundary

GitHub Actions is the verification authority and uses Go 1.27. The local
workflow deliberately does not ask contributors to run Go build, test, race,
vet, or formatting commands. See [docs/rfcs/proof-kernel-boundary-v1.md](docs/rfcs/proof-kernel-boundary-v1.md).
