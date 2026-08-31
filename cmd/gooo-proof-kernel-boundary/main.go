package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kimjooyoon/gooo-proof-kernel-boundary/internal/evaluator"
	"github.com/kimjooyoon/gooo-proof-kernel-boundary/internal/kernel"
)

type contract struct {
	Schema string `json:"schema"`
	Total  int    `json:"total"`
	Fixed  bool   `json:"fixed"`
	Cells  []struct {
		Ordinal  int    `json:"ordinal"`
		ID       string `json:"id"`
		Activity string `json:"activity"`
		MetricID string `json:"metric_id"`
	} `json:"cells"`
}

type semanticIR struct {
	Schema       string       `json:"schema"`
	Source       string       `json:"source"`
	SourceDigest string       `json:"source_digest"`
	Nodes        []irNode     `json:"nodes"`
}

type irNode struct {
	ID       string `json:"id"`
	Activity string `json:"activity"`
	SourceLine int   `json:"source_line"`
	MetricID string `json:"metric_id"`
	Artifact string `json:"artifact"`
	Evaluator string `json:"evaluator"`
}

type report struct {
	Schema                      string                    `json:"schema"`
	Decision                    string                    `json:"decision"`
	Precedence                  []string                  `json:"precedence"`
	ContractDigest              string                    `json:"contract_digest"`
	SourceDigest                string                    `json:"source_digest"`
	SemanticIRDigest            string                    `json:"semantic_ir_digest"`
	FixedDenominator            int                       `json:"fixed_denominator"`
	KernelVersion               string                    `json:"kernel_version"`
	KernelAPISurfaceCount       int                       `json:"kernel_api_surface_count"`
	Cases                       []evaluator.CaseResult    `json:"cases"`
	Summary                     summary                   `json:"summary"`
	Authority                   authority                 `json:"authority"`
	Improvement                 improvement               `json:"improvement"`
	ExpectedStatusMismatches    []string                  `json:"expected_status_mismatches"`
}

type summary struct {
	Total   int `json:"total"`
	Normal  int `json:"normal"`
	Unknown int `json:"unknown"`
	Refuted int `json:"refuted"`
}

type authority struct {
	AllowedOperations []string `json:"allowed_operations"`
	DeniedOperations  []string `json:"denied_operations"`
	RepositoryWrites  int      `json:"repository_writes"`
	LocalTestExecutions int    `json:"local_test_executions"`
	CrossProjectRequiredGates int `json:"cross_project_required_gates"`
	ReadOnly           bool     `json:"read_only"`
}

type improvement struct {
	Status  string               `json:"status"`
	Unknown kernel.UnknownTuple  `json:"unknown"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "gooo-proof-kernel-boundary/v1")
		return 0
	case "compile":
		return compile(args[1:], stdout, stderr)
	case "evaluate":
		return evaluate(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func compile(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("compile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcePath := flags.String("source", "examples/proof-kernel-boundary/main.gooo", "Gooo source")
	contractPath := flags.String("contract", "contracts/proof-kernel-boundary-denominator-v1.json", "fixed denominator")
	outputPath := flags.String("output", "semantic-ir.json", "semantic IR output")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	source, err := os.ReadFile(*sourcePath)
	if err != nil {
		return emitError(stderr, "read source", err)
	}
	contractData, err := os.ReadFile(*contractPath)
	if err != nil {
		return emitError(stderr, "read contract", err)
	}
	var c contract
	if err := json.Unmarshal(contractData, &c); err != nil {
		return emitError(stderr, "decode contract", err)
	}
	activities := parseActivities(string(source))
	if c.Schema != "gooo/proof-kernel-boundary/denominator/v1" || !c.Fixed || c.Total != 12 || len(c.Cells) != 12 || len(activities) != 12 {
		return emitError(stderr, "compile source", fmt.Errorf("source and fixed denominator must each contain exactly 12 activities/cells"))
	}
	byActivity := make(map[string]struct {
		metricID string
	}, len(c.Cells))
	for _, cell := range c.Cells {
		byActivity[cell.Activity] = struct{metricID string}{cell.MetricID}
	}
	nodes := make([]irNode, 0, len(activities))
	for _, activity := range activities {
		cell, ok := byActivity[activity.name]
		if !ok {
			return emitError(stderr, "compile source", fmt.Errorf("activity %q is not in denominator", activity.name))
		}
		nodes = append(nodes, irNode{ID: "gooo://proof-kernel-boundary/activity/" + kebab(activity.name), Activity: activity.name, SourceLine: activity.line, MetricID: cell.metricID, Artifact: "internal/evaluator/generated.go", Evaluator: "internal/evaluator/generated.go"})
	}
	ir := semanticIR{Schema: "gooo/proof-kernel-boundary/ir/v1", Source: *sourcePath, SourceDigest: kernel.Digest(source), Nodes: nodes}
	if err := writeJSON(*outputPath, ir); err != nil {
		return emitError(stderr, "write semantic IR", err)
	}
	return writeJSONTo(stdout, ir)
}

func evaluate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcePath := flags.String("source", "examples/proof-kernel-boundary/main.gooo", "Gooo source")
	contractPath := flags.String("contract", "contracts/proof-kernel-boundary-denominator-v1.json", "fixed denominator")
	irPath := flags.String("ir", "semantic-ir.json", "semantic IR")
	casesPath := flags.String("cases", "fixtures/cases", "controlled cases")
	outputDir := flags.String("output-dir", "", "caller-owned output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *outputDir == "" {
		return emitError(stderr, "evaluate", fmt.Errorf("--output-dir is required"))
	}
	source, err := os.ReadFile(*sourcePath)
	if err != nil {
		return emitError(stderr, "read source", err)
	}
	contractData, err := os.ReadFile(*contractPath)
	if err != nil {
		return emitError(stderr, "read contract", err)
	}
	var c contract
	if err := json.Unmarshal(contractData, &c); err != nil {
		return emitError(stderr, "decode contract", err)
	}
	irData, err := os.ReadFile(*irPath)
	if err != nil {
		return emitError(stderr, "read semantic IR", err)
	}
	var ir semanticIR
	if err := json.Unmarshal(irData, &ir); err != nil || ir.Schema != "gooo/proof-kernel-boundary/ir/v1" || ir.SourceDigest != kernel.Digest(source) || len(ir.Nodes) != 12 {
		return emitError(stderr, "verify semantic IR", fmt.Errorf("semantic IR is not bound to the current Gooo source"))
	}
	contractDigest := kernel.Digest(contractData)
	paths, err := filepath.Glob(filepath.Join(*casesPath, "*.json"))
	if err != nil || len(paths) != 12 {
		return emitError(stderr, "load cases", fmt.Errorf("exactly 12 JSON cases are required"))
	}
	sort.Strings(paths)
	results := make([]evaluator.CaseResult, 0, len(paths))
	seen := map[string]bool{}
	denied := map[string]bool{}
	mismatches := []string{}
	for _, path := range paths {
		input, err := evaluator.DecodeCase(path)
		if err != nil {
			return emitError(stderr, "decode case", err)
		}
		if input.Schema != evaluator.CaseSchema || input.CaseID == "" || seen[input.CaseID] {
			return emitError(stderr, "validate case", fmt.Errorf("case IDs must be unique and use %s", evaluator.CaseSchema))
		}
		seen[input.CaseID] = true
		if input.ContractDigest == "" {
			input.ContractDigest = contractDigest
			input.ContractDigestVerified = true
		}
		if input.ObservedDenominator == 0 {
			input.ObservedDenominator = kernel.FixedDenominator
		}
		if len(input.ObservedPrecedence) == 0 {
			input.ObservedPrecedence = append([]string(nil), kernel.Precedence...)
		}
		if input.DigestVerifier == "" {
			input.DigestVerifier = kernel.DigestVerifierID
		}
		result := evaluator.EvaluateCase(input, contractDigest)
		results = append(results, result)
		if result.ExpectedStatus != "" && result.ExpectedStatus != result.Status {
			mismatches = append(mismatches, result.CaseID)
		}
		for _, operation := range result.DeniedOperations {
			denied[operation] = true
		}
	}
	report := report{Schema: "gooo/proof-kernel-boundary/report/v1", Decision: decide(results), Precedence: append([]string(nil), kernel.Precedence...), ContractDigest: contractDigest, SourceDigest: kernel.Digest(source), SemanticIRDigest: kernel.Digest(irData), FixedDenominator: kernel.FixedDenominator, KernelVersion: kernel.Version, KernelAPISurfaceCount: kernel.KernelAPISurfaceCount, Cases: results, ExpectedStatusMismatches: mismatches, Authority: authority{AllowedOperations: []string{kernel.AllowedRead, kernel.AllowedReportWrite}, DeniedOperations: mapKeys(denied), RepositoryWrites: 0, LocalTestExecutions: 0, CrossProjectRequiredGates: 0, ReadOnly: true}, Improvement: improvement{Status: kernel.Unknown, Unknown: kernel.UnknownTuple{Stage: "IMPROVEMENT", Step: "COMPARE_EXACT_BEFORE_AFTER_PAIR", Reason: "EXACT_COMPARABLE_PAIR_MISSING", UnknownClass: "DIRECT_MISSING", NextOperation: "PROVIDE_EXACT_COMPARABLE_PAIR", BlockedBy: []string{}}}}
	for _, result := range results {
		switch result.Status {
		case kernel.Closed:
			report.Summary.Normal++
		case kernel.Unknown:
			report.Summary.Unknown++
		case kernel.Refuted:
			report.Summary.Refuted++
		}
	}
	report.Summary.Total = len(results)
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return emitError(stderr, "create output directory", err)
	}
	if err := writeJSON(filepath.Join(*outputDir, "evaluation.json"), report); err != nil {
		return emitError(stderr, "write evaluation", err)
	}
	return writeJSONTo(stdout, report)
}

func decide(results []evaluator.CaseResult) string {
	for _, result := range results {
		if result.Status == kernel.Refuted {
			return kernel.Refuted
		}
	}
	for _, result := range results {
		if result.Status == kernel.Unknown {
			return kernel.Unknown
		}
	}
	return kernel.Closed
}

type activity struct { name string; line int }

func parseActivities(source string) []activity {
	var result []activity
	for lineNumber, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "activity ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "activity "))
		open := strings.IndexByte(rest, '(')
		if open > 0 {
			result = append(result, activity{name: strings.TrimSpace(rest[:open]), line: lineNumber + 1})
		}
	}
	return result
}

func kebab(value string) string {
	var builder strings.Builder
	for index, character := range value {
		if character >= 'A' && character <= 'Z' {
			if index > 0 { builder.WriteByte('-') }
			builder.WriteRune(character + ('a' - 'A'))
		} else { builder.WriteRune(character) }
	}
	return builder.String()
}

func mapKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key := range values { result = append(result, key) }
	sort.Strings(result)
	return result
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
	file, err := os.Create(path)
	if err != nil { return err }
	defer file.Close()
	return writeJSONTo(file, value)
}

func writeJSONTo(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func emitError(stderr io.Writer, prefix string, err error) int {
	fmt.Fprintf(stderr, "%s: %v\n", prefix, err)
	return 1
}

func usage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: gooo-proof-kernel-boundary compile --source PATH --contract PATH --output PATH")
	fmt.Fprintln(stderr, "       gooo-proof-kernel-boundary evaluate --source PATH --contract PATH --ir PATH --cases PATH --output-dir PATH")
}
