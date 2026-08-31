package evaluator

import (
	"encoding/json"
	"os"

	"github.com/kimjooyoon/gooo-proof-kernel-boundary/internal/kernel"
)

const CaseSchema = "gooo/proof-kernel-boundary/case/v1"

type CaseInput struct {
	Schema                   string                `json:"schema"`
	CaseID                   string                `json:"case_id"`
	CandidateStatus          string                `json:"candidate_status"`
	ContractDigest           string                `json:"contract_digest"`
	ContractDigestVerified   bool                  `json:"contract_digest_verified"`
	DigestVerifier           string                `json:"digest_verifier"`
	KernelVerdictOverride    string                `json:"kernel_verdict_override"`
	PrecedenceOverride       []string              `json:"precedence_override"`
	DenominatorOverride      *int                  `json:"denominator_override"`
	DigestVerifierOverride   string                `json:"digest_verifier_override"`
	AuthorityCeilingOverride []string              `json:"authority_ceiling_override"`
	SelfTrusted              bool                  `json:"self_trusted"`
	ObservedDenominator      int                   `json:"observed_denominator"`
	ObservedPrecedence       []string              `json:"observed_precedence"`
	AuthorityOperations      []string              `json:"authority_operations"`
	ParentKernelChanged      bool                  `json:"parent_kernel_changed"`
	ParentRelease            *kernel.ParentRelease `json:"parent_release"`
	HumanAuthorization       *kernel.HumanAuthorization `json:"human_authorization"`
	Unknown                  *kernel.UnknownTuple `json:"unknown"`
	ExpectedStatus           string                `json:"expected_status"`
}

type CaseResult struct {
	CaseID               string              `json:"case_id"`
	ExpectedStatus       string              `json:"expected_status"`
	Kernel               kernel.Verdict      `json:"kernel"`
	Status               string              `json:"status"`
	Unknown              *kernel.UnknownTuple `json:"unknown"`
	AllowedOperations   []string             `json:"allowed_operations"`
	DeniedOperations    []string             `json:"denied_operations"`
}

func DecodeCase(path string) (CaseInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CaseInput{}, err
	}
	var input CaseInput
	if err := json.Unmarshal(data, &input); err != nil {
		return CaseInput{}, err
	}
	return input, nil
}

func EvaluateCase(input CaseInput, contractDigest string) CaseResult {
	kernelInput := kernel.Input{
		CaseID:                    input.CaseID,
		CandidateStatus:           input.CandidateStatus,
		Unknown:                   input.Unknown,
		ContractDigest:            input.ContractDigest,
		ExpectedContractDigest:    contractDigest,
		ContractDigestVerified:    input.ContractDigestVerified,
		DigestVerifier:            input.DigestVerifier,
		KernelVerdictOverride:     input.KernelVerdictOverride,
		PrecedenceOverride:        input.PrecedenceOverride,
		DenominatorOverride:       input.DenominatorOverride,
		DigestVerifierOverride:    input.DigestVerifierOverride,
		AuthorityCeilingOverride:  input.AuthorityCeilingOverride,
		SelfTrusted:               input.SelfTrusted,
		ObservedDenominator:       input.ObservedDenominator,
		ObservedPrecedence:        input.ObservedPrecedence,
		AuthorityOperations:       input.AuthorityOperations,
		ParentKernelChanged:       input.ParentKernelChanged,
		ParentRelease:             input.ParentRelease,
		HumanAuthorization:        input.HumanAuthorization,
	}
	verdict := Evaluate(kernelInput)
	return CaseResult{
		CaseID:             input.CaseID,
		ExpectedStatus:     input.ExpectedStatus,
		Kernel:             verdict,
		Status:             verdict.Status,
		Unknown:            verdict.Unknown,
		AllowedOperations:  verdict.AllowedOperations,
		DeniedOperations:   verdict.DeniedOperations,
	}
}
