// Command evidence-audit validates an offline evidence-disposition bundle.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Autumn-27/artex/internal/evidenceaudit"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("evidence-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "path to an evidence-audit/v2 JSON bundle")
	output := flags.String("output", "", "new output path (default: stdout)")
	strict := flags.Bool("strict", false, "return exit code 1 for attention reports")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *input == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: evidence-audit -input bundle.json [-output report.json] [-strict]")
		return 2
	}

	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintf(stderr, "open input: %v\n", err)
		return 2
	}
	bundle, bundleSHA256, err := evidenceaudit.Load(file)
	closeErr := file.Close()
	if err != nil {
		fmt.Fprintf(stderr, "parse input: %v\n", err)
		return 2
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "close input: %v\n", closeErr)
		return 2
	}

	report := evidenceaudit.New(filepath.Dir(*input)).Audit(bundle, bundleSHA256)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode report: %v\n", err)
		return 2
	}
	raw = append(raw, '\n')
	if *output == "" {
		if _, err := stdout.Write(raw); err != nil {
			fmt.Fprintf(stderr, "write report: %v\n", err)
			return 2
		}
	} else {
		if err := writeExclusive(*output, raw); err != nil {
			fmt.Fprintf(stderr, "write report: %v\n", err)
			return 2
		}
	}
	if report.Result == "invalid" || (*strict && report.Result == "attention") {
		return 1
	}
	return 0
}

func writeExclusive(path string, data []byte) error {
	if path == "" {
		return errors.New("output path is empty")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
