// Package kernel is the trusted proof kernel. Its exported surface is kept
// deliberately small; generated policy code may call Verify but may not supply
// a replacement for any of the constants or checks below.
package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	Version              = "gooo/proof-kernel-boundary/kernel/v1"
	TrustedKernelDigest  = "sha256:6a3f31f11cd2b4cc9cf9f6b0c4c9fc3b8a3d8e4d6fa4f5ad1cb6c05e4c8c8d11"
	DigestVerifierID     = "trusted-sha256-v1"
	FixedDenominator     = 12
	Closed               = "CLOSED"
	Unknown              = "UNKNOWN"
	Refuted              = "REFUTED"
	AllowedRead          = "READ_IMMUTABLE_INPUT"
	AllowedReportWrite   = "WRITE_CALLER_OWNED_REPORT"
	KernelAPISurfaceCount = 8
)

var Precedence = []string{Refuted, Unknown, Closed}

type UnknownTuple struct {
	Stage         string   `json:"stage"`
	Step          string   `json:"step"`
	Reason        string   `json:"reason"`
	UnknownClass  string   `json:"unknown_class"`
	NextOperation string   `json:"next_operation"`
	BlockedBy     []string `json:"blocked_by"`
}

type ParentRelease struct {
	Tag         string `json:"tag"`
	CommitSHA   string `json:"commit_sha"`
	ReleaseDigest string `json:"release_digest"`
	AssetDigest string `json:"asset_digest"`
	Immutable   bool   `json:"immutable"`
}

type HumanAuthorization struct {
	ReceiptID          string `json:"receipt_id"`
	HumanID            string `json:"human_id"`
	AuthorizedParentDigest string `json:"authorized_parent_digest"`
	AuthorizedOperation string `json:"authorized_operation"`
	ReceiptDigest      string `json:"receipt_digest"`
}

type Input struct {
	CaseID                    string               `json:"case_id"`
	CandidateStatus           string               `json:"candidate_status"`
	Unknown                   *UnknownTuple        `json:"unknown"`
	ContractDigest            string               `json:"contract_digest"`
	ExpectedContractDigest    string               `json:"expected_contract_digest"`
	ContractDigestVerified    bool                 `json:"contract_digest_verified"`
	DigestVerifier            string               `json:"digest_verifier"`
	KernelVerdictOverride     string               `json:"kernel_verdict_override"`
	PrecedenceOverride        []string             `json:"precedence_override"`
	DenominatorOverride       *int                 `json:"denominator_override"`
	DigestVerifierOverride    string               `json:"digest_verifier_override"`
	AuthorityCeilingOverride  []string             `json:"authority_ceiling_override"`
	SelfTrusted               bool                 `json:"self_trusted"`
	ObservedDenominator       int                  `json:"observed_denominator"`
	ObservedPrecedence        []string             `json:"observed_precedence"`
	AuthorityOperations       []string             `json:"authority_operations"`
	ParentKernelChanged       bool                 `json:"parent_kernel_changed"`
	ParentRelease             *ParentRelease       `json:"parent_release"`
	HumanAuthorization       *HumanAuthorization  `json:"human_authorization"`
}

type Verdict struct {
	KernelVersion        string        `json:"kernel_version"`
	Status               string        `json:"status"`
	Decision             string        `json:"decision"`
	Reason               string        `json:"reason"`
	Precedence           []string      `json:"precedence"`
	Unknown              *UnknownTuple `json:"unknown"`
	AllowedOperations   []string      `json:"allowed_operations"`
	DeniedOperations    []string      `json:"denied_operations"`
	KernelAPISurfaceCount int         `json:"kernel_api_surface_count"`
}

func Verify(input Input) Verdict {
	verdict := Verdict{
		KernelVersion:          Version,
		Status:                 Refuted,
		Decision:               Refuted,
		Reason:                 "KERNEL_VERIFICATION_NOT_COMPLETE",
		Precedence:             append([]string(nil), Precedence...),
		AllowedOperations:      []string{AllowedRead, AllowedReportWrite},
		DeniedOperations:       []string{},
		KernelAPISurfaceCount:   KernelAPISurfaceCount,
	}

	if input.KernelVerdictOverride != "" {
		verdict.Reason = "KERNEL_VERDICT_OVERRIDE_REFUTED"
		return verdict
	}
	if len(input.PrecedenceOverride) > 0 {
		verdict.Reason = "PRECEDENCE_OVERRIDE_REFUTED"
		return verdict
	}
	if input.DenominatorOverride != nil {
		verdict.Reason = "DENOMINATOR_OVERRIDE_REFUTED"
		return verdict
	}
	if input.DigestVerifierOverride != "" {
		verdict.Reason = "DIGEST_VERIFIER_OVERRIDE_REFUTED"
		return verdict
	}
	if len(input.AuthorityCeilingOverride) > 0 {
		verdict.Reason = "AUTHORITY_CEILING_OVERRIDE_REFUTED"
		return verdict
	}
	for _, operation := range input.AuthorityOperations {
		if operation != AllowedRead && operation != AllowedReportWrite {
			verdict.DeniedOperations = append(verdict.DeniedOperations, operation)
		}
	}
	if len(verdict.DeniedOperations) > 0 {
		verdict.Reason = "AUTHORITY_OPERATION_EXCEEDS_CEILING"
		return verdict
	}
	if input.SelfTrusted {
		verdict.Reason = "SELF_TRUST_REFUTED"
		return verdict
	}
	if input.ObservedDenominator != FixedDenominator {
		verdict.Reason = "DENOMINATOR_NOT_FIXED_AT_12"
		return verdict
	}
	if !sameStrings(input.ObservedPrecedence, Precedence) {
		verdict.Reason = "PRECEDENCE_NOT_KERNEL_OWNED"
		return verdict
	}
	if !input.ContractDigestVerified || !IsSHA256Digest(input.ContractDigest) || input.ContractDigest != input.ExpectedContractDigest || input.DigestVerifier != DigestVerifierID {
		verdict.Reason = "DIGEST_VERIFICATION_NOT_TRUSTED"
		return verdict
	}
	if input.ParentKernelChanged {
		if input.ParentRelease == nil {
			return unknownVerdict(verdict, "KERNEL_CHANGE", "VERIFY_PARENT_RELEASE", "IMMUTABLE_PARENT_RELEASE_MISSING", "DIRECT_MISSING", "PROVIDE_IMMUTABLE_PARENT_RELEASE_AND_HUMAN_RECEIPT", []string{})
		}
		if !input.ParentRelease.Immutable || input.ParentRelease.Tag == "" || input.ParentRelease.CommitSHA == "" || !IsSHA256Digest(input.ParentRelease.ReleaseDigest) || !IsSHA256Digest(input.ParentRelease.AssetDigest) {
			verdict.Reason = "PARENT_RELEASE_NOT_IMMUTABLE"
			return verdict
		}
		if input.HumanAuthorization == nil {
			return unknownVerdict(verdict, "KERNEL_CHANGE", "VERIFY_HUMAN_AUTHORIZATION", "HUMAN_AUTHORIZATION_RECEIPT_MISSING", "DEPENDENCY_BLOCKED", "PROVIDE_SEPARATE_HUMAN_AUTHORIZATION_RECEIPT", []string{"parent-release", "human-authorization"})
		}
		if input.HumanAuthorization.AuthorizedParentDigest != input.ParentRelease.ReleaseDigest || input.HumanAuthorization.AuthorizedOperation != "CHANGE_TRUSTED_KERNEL" || input.HumanAuthorization.HumanID == "" || !IsSHA256Digest(input.HumanAuthorization.ReceiptDigest) {
			verdict.Reason = "HUMAN_AUTHORIZATION_DOES_NOT_MATCH_PARENT_RELEASE"
			return verdict
		}
	}

	switch input.CandidateStatus {
	case Closed:
		verdict.Status = Closed
		verdict.Decision = Closed
		verdict.Reason = "KERNEL_VERIFIED_CLOSED"
		return verdict
	case Unknown:
		if !validUnknown(input.Unknown) {
			verdict.Reason = "UNKNOWN_TUPLE_INCOMPLETE"
			return verdict
		}
		verdict.Status = Unknown
		verdict.Decision = Unknown
		verdict.Reason = input.Unknown.Reason
		verdict.Unknown = input.Unknown
		return verdict
	case Refuted:
		verdict.Reason = "CANDIDATE_ALREADY_REFUTED"
		return verdict
	default:
		verdict.Reason = "UNRECOGNIZED_CANDIDATE_STATUS"
		return verdict
	}
}

func unknownVerdict(verdict Verdict, stage, step, reason, class, next string, blocked []string) Verdict {
	unknown := &UnknownTuple{Stage: stage, Step: step, Reason: reason, UnknownClass: class, NextOperation: next, BlockedBy: blocked}
	verdict.Status = Unknown
	verdict.Decision = Unknown
	verdict.Reason = reason
	verdict.Unknown = unknown
	return verdict
}

func validUnknown(unknown *UnknownTuple) bool {
	if unknown == nil || unknown.Stage == "" || unknown.Step == "" || unknown.Reason == "" || unknown.UnknownClass == "" || unknown.NextOperation == "" || unknown.BlockedBy == nil {
		return false
	}
	if unknown.UnknownClass == "DIRECT_MISSING" {
		return len(unknown.BlockedBy) == 0
	}
	return unknown.UnknownClass == "DEPENDENCY_BLOCKED" && len(unknown.BlockedBy) > 0
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func IsSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
