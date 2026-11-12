package verification_test

import (
	"context"
	"testing"
	"time"

	"github.com/Autumn-27/artex/internal/verificationlab"
	"github.com/Autumn-27/artex/verification"
)

func TestHTTPOracleRealResponses(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"vulnerable", "reproduced"}, {"fixed", "not_reproduced"}, {"business_denial", "not_reproduced"}, {"waf", "inconclusive"}, {"public", "inconclusive"}, {"inconsistent", "inconclusive"}, {"wrong_object", "inconclusive"}, {"oversize", "inconclusive"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			lab := verificationlab.New(verificationlab.Options{Mode: tc.mode})
			defer lab.Close()
			obs := (verification.Runner{}).Run(t.Context(), lab.Case, nil)
			got, reason := verification.Evaluate(lab.Case, obs)
			if got != tc.want {
				t.Fatalf("got %s (%s), want %s", got, reason, tc.want)
			}
			if got == "reproduced" {
				obs[3].Body = []byte(`{"secret":"forged"}`)
				if v, _ := verification.Evaluate(lab.Case, obs); v == "reproduced" {
					t.Fatal("tampered receipt accepted")
				}
			}
		})
	}
}

func TestHTTPExpiredLoginRecovery(t *testing.T) {
	lab := verificationlab.New(verificationlab.Options{Expired: true})
	defer lab.Close()
	r := verification.Runner{}
	obs := r.Run(t.Context(), lab.Case, nil)
	if v, reason := verification.Evaluate(lab.Case, obs); v != "inconclusive" || reason != "owner_identity_invalid" {
		t.Fatalf("lost prerequisite failure: %s %s", v, reason)
	}
	refresh, auth, err := r.Refresh(t.Context(), lab.Case)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verification.RefreshedAuth(lab.Case, refresh); err != nil {
		t.Fatal(err)
	}
	obs = r.Run(t.Context(), lab.Case, auth)
	if v, reason := verification.Evaluate(lab.Case, obs); v != "reproduced" {
		t.Fatalf("not recovered: %s %s", v, reason)
	}
	if len(lab.Requests()) != 10 {
		t.Fatalf("unexpected actual request count %d", len(lab.Requests()))
	}
}

func TestHTTPInterruptionAndBudget(t *testing.T) {
	lab := verificationlab.New(verificationlab.Options{Mode: "cancel"})
	defer lab.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	obs := (verification.Runner{}).Run(ctx, lab.Case, nil)
	if v, _ := verification.Evaluate(lab.Case, obs); v != "inconclusive" {
		t.Fatal(v)
	}
	r := verification.Runner{Reserve: func(context.Context) error { return context.DeadlineExceeded }}
	before := len(lab.Requests())
	obs = r.Run(t.Context(), lab.Case, nil)
	if len(lab.Requests()) != before {
		t.Fatal("request escaped budget")
	}
	if v, _ := verification.Evaluate(lab.Case, obs); v != "inconclusive" {
		t.Fatal(v)
	}
}
