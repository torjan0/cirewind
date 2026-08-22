package model

import (
	"os"
	"strings"
	"testing"
)

var forensicInvariants = []string{
	"Action downloaded != Action executed",
	"Repository possesses a secret != affected step could read that secret",
	"id-token: write != cloud role assumed",
	"Workflow ran during incident window != compromised SHA executed",
	"Current tag points to a safe commit != historical runs were safe",
	"No retained logs != no compromise",
	"Deployment followed an affected step != attacker caused the deployment",
	"Present-day workflow YAML != historical workflow definition",
}

func TestCanonicalContractsRemainVisibleInNormativeDocs(t *testing.T) {
	documents := []string{"../../docs/EVIDENCE_MODEL.md", "../../docs/TEST_STRATEGY.md"}
	for _, name := range documents {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, invariant := range forensicInvariants {
			if !strings.Contains(text, invariant) {
				t.Errorf("%s omits forensic invariant %q", name, invariant)
			}
		}
		for _, state := range FindingStates() {
			if !strings.Contains(text, string(state)) {
				t.Errorf("%s omits canonical finding state %s", name, state)
			}
		}
		if name == "../../docs/EVIDENCE_MODEL.md" {
			for _, level := range ProvenanceLevels() {
				if !strings.Contains(text, string(level)) {
					t.Errorf("%s omits canonical provenance level %s", name, level)
				}
			}
		}
	}
}
