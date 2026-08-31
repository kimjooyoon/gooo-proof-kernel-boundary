package evaluator

import (
	"testing"

	"github.com/kimjooyoon/gooo-proof-kernel-boundary/internal/kernel"
)

func TestGeneratedEvaluatorCannotChangeKernelVerdict(t *testing.T) {
	input := CaseInput{Schema: CaseSchema, CaseID: "override", CandidateStatus: kernel.Closed, KernelVerdictOverride: kernel.Closed}
	result := EvaluateCase(input, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if result.Status != kernel.Refuted || result.Kernel.Reason != "KERNEL_VERDICT_OVERRIDE_REFUTED" {
		t.Fatalf("got %+v", result)
	}
}
