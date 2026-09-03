package packfixtures

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/torjan0/cirewind/internal/model"
)

func TestReviewdogScenariosAreDeterministicAndBounded(t *testing.T) {
	ctx := context.Background()
	first, err := Generate(ctx, "CIR-REVIEWDOG-ACTION-SETUP-2025", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Generate(ctx, "CIR-REVIEWDOG-ACTION-SETUP-2025", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 12 || len(first) != len(second) {
		t.Fatalf("scenario count = %d", len(first))
	}
	for index := range first {
		a, err := json.Marshal(first[index].Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(second[index].Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if first[index].ID != second[index].ID || !bytes.Equal(a, b) {
			t.Fatalf("scenario %s is not deterministic", first[index].ID)
		}
		if index > 0 && first[index-1].ID >= first[index].ID {
			t.Fatalf("scenarios are not sorted: %s then %s", first[index-1].ID, first[index].ID)
		}
		text := string(a)
		if strings.Contains(text, "3f401fe1d58fe77e10d665ab713057375e39b887") {
			t.Fatalf("scenario %s names the unreviewed retag object", first[index].ID)
		}
		for _, forbidden := range []string{"gist.github", "B64_BLOB", "ghp_", "-----BEGIN"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("scenario %s contains payload-like content %q", first[index].ID, forbidden)
			}
		}
		if !strings.Contains(text, "cirewind-fixtures/reviewdog-consumer") {
			t.Fatalf("scenario %s does not use the reserved synthetic consumer", first[index].ID)
		}
	}
	states := map[string]bool{}
	for _, scenario := range first {
		for _, forbidden := range scenario.Forbidden {
			if !forbidden.State.Valid() || forbidden.Rationale == "" {
				t.Fatalf("scenario %s carries an invalid forbidden state", scenario.ID)
			}
			states[string(forbidden.State)] = true
		}
	}
	if !states[string(model.ConfirmedExecuted)] || !states[string(model.RunInWindowMutableRef)] || !states[string(model.NoMatchConfirmed)] {
		t.Fatalf("forbidden states do not cover execution, window, and clean-result promotions: %v", states)
	}
	if _, err := Generate(ctx, "CIR-UNKNOWN", "1.0.0"); err == nil {
		t.Fatal("unregistered incident produced fixtures")
	}
	if registered := Registered(); len(registered) != 2 || registered[0] != "CIR-REVIEWDOG-ACTION-SETUP-2025/1.0.0" || registered[1] != "CIR-TJ-ACTIONS-CHANGED-FILES-2025/1.0.0" {
		t.Fatalf("registered=%v", registered)
	}
	tj, err := Generate(ctx, "CIR-TJ-ACTIONS-CHANGED-FILES-2025", "1.0.0")
	if err != nil || len(tj) != 12 {
		t.Fatalf("tj-actions scenarios=%d err=%v", len(tj), err)
	}
	for _, scenario := range tj {
		data, err := json.Marshal(scenario.Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "tj-actions/changed-files") || strings.Contains(string(data), "gist.github") {
			t.Fatalf("tj-actions scenario %s is not bounded to the affected component", scenario.ID)
		}
	}
}
