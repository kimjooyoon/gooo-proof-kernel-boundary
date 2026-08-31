package kernel

import "testing"

func validInput() Input {
	return Input{
		CaseID:                 "test",
		CandidateStatus:        Closed,
		ContractDigest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ExpectedContractDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ContractDigestVerified: true,
		DigestVerifier:         DigestVerifierID,
		ObservedDenominator:   FixedDenominator,
		ObservedPrecedence:    append([]string(nil), Precedence...),
	}
}

func TestKernelOwnsOverrides(t *testing.T) {
	checks := []struct {
		name   string
		mutate func(*Input)
		reason string
	}{
		{"verdict", func(input *Input) { input.KernelVerdictOverride = Closed }, "KERNEL_VERDICT_OVERRIDE_REFUTED"},
		{"precedence", func(input *Input) { input.PrecedenceOverride = []string{Closed} }, "PRECEDENCE_OVERRIDE_REFUTED"},
		{"denominator", func(input *Input) { value := 11; input.DenominatorOverride = &value }, "DENOMINATOR_OVERRIDE_REFUTED"},
		{"digest", func(input *Input) { input.DigestVerifierOverride = "md5" }, "DIGEST_VERIFIER_OVERRIDE_REFUTED"},
		{"authority", func(input *Input) { input.AuthorityCeilingOverride = []string{"WRITE_SOURCE"} }, "AUTHORITY_CEILING_OVERRIDE_REFUTED"},
		{"self-trust", func(input *Input) { input.SelfTrusted = true }, "SELF_TRUST_REFUTED"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			input := validInput()
			check.mutate(&input)
			verdict := Verify(input)
			if verdict.Status != Refuted || verdict.Reason != check.reason {
				t.Fatalf("got %+v", verdict)
			}
		})
	}
}

func TestKernelPreservesUnknownCoordinates(t *testing.T) {
	input := validInput()
	input.CandidateStatus = Unknown
	input.Unknown = &UnknownTuple{Stage: "EVIDENCE", Step: "READ", Reason: "MISSING", UnknownClass: "DIRECT_MISSING", NextOperation: "PROVIDE", BlockedBy: []string{}}
	verdict := Verify(input)
	if verdict.Status != Unknown || verdict.Unknown == nil || verdict.Unknown.UnknownClass != "DIRECT_MISSING" || len(verdict.Unknown.BlockedBy) != 0 {
		t.Fatalf("got %+v", verdict)
	}
}

func TestKernelDoesNotCloseUnownedKernelChange(t *testing.T) {
	input := validInput()
	input.ParentKernelChanged = true
	verdict := Verify(input)
	if verdict.Status != Unknown || verdict.Unknown == nil || verdict.Unknown.UnknownClass != "DIRECT_MISSING" {
		t.Fatalf("got %+v", verdict)
	}
}
