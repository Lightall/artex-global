package db

import (
	"testing"

	"github.com/Autumn-27/artex/internal/experimenttest"
	"github.com/Autumn-27/artex/securityexperiment"
	"github.com/Autumn-27/artex/verification"
)

func localVerificationConfig(spec securityexperiment.Spec) verification.Config {
	return verification.Config{Cases: []verification.Case{{
		ID: "legacy-local", RuleSource: "operator-owned isolation rule", URL: spec.Origin + spec.ResourcePath,
		ObjectID: spec.ObjectID, ObjectPointer: spec.ObjectPointer, OwnerPointer: spec.OwnerPointer,
		PrivatePointer: "/private", ValuePointer: "/value", DenialPointer: "/denied", DenialValue: "true",
		Owner: verification.Actor{ID: spec.Owner.PrincipalID, IdentityURL: spec.Origin + spec.IdentityPath, IdentityPointer: spec.PrincipalPointer},
		Other: verification.Actor{ID: spec.Other.PrincipalID, IdentityURL: spec.Origin + spec.IdentityPath, IdentityPointer: spec.PrincipalPointer},
	}}, RequiredFindings: 1, MaxRequests: 20}
}

func TestVerificationModesCannotReplaceEachOthersRequirements(t *testing.T) {
	for _, experimentFirst := range []bool{true, false} {
		name := "http_first"
		if experimentFirst {
			name = "experiment_first"
		}
		t.Run(name, func(t *testing.T) {
			d, task, store, goal := experimentDB(t)
			target, spec := experimenttest.New(t)
			cfg := localVerificationConfig(spec)
			if experimentFirst {
				if _, err := store.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec); err != nil {
					t.Fatal(err)
				}
				if err := d.SetHTTPVerificationConfig(t.Context(), task.ID, cfg); err == nil {
					t.Fatal("HTTP configuration replaced experiment proof requirements")
				}
				stored, err := d.HTTPVerificationConfig(t.Context(), task.ID)
				if err != nil || len(stored.Cases) != 0 {
					t.Fatalf("rejected configuration was partly persisted: %v %v", stored, err)
				}
			} else {
				if err := d.SetHTTPVerificationConfig(t.Context(), task.ID, cfg); err != nil {
					t.Fatal(err)
				}
				if _, err := store.CreateSecurityExperimentCase(t.Context(), task.ID, goal, spec); err == nil {
					t.Fatal("experiment configuration replaced HTTP proof requirements")
				}
				has, err := store.HasSecurityExperimentGoals()
				if err != nil || has {
					t.Fatalf("rejected experiment left a partial requirement: %v %v", has, err)
				}
				stored, err := d.HTTPVerificationConfig(t.Context(), task.ID)
				if err != nil || len(stored.Cases) != 1 || stored.Cases[0].ID != cfg.Cases[0].ID {
					t.Fatalf("original HTTP configuration was lost: %v %v", stored, err)
				}
			}
			if target.Calls.Load() != 0 {
				t.Fatal("configuration performed network probes")
			}
		})
	}
}
