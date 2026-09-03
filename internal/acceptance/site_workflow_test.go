package acceptance_test

import (
	"reflect"
	"strings"
	"testing"
)

// TestSiteValidationWorkflowIsReadOnlyAndNeverDeploys pins the SITE-004
// contract: sample-site validation runs on pull requests and main with no
// default permissions, exactly one read-only job, ledger-pinned actions only,
// a credential-free checkout, and no Pages, artifact, or deployment step.
func TestSiteValidationWorkflowIsReadOnlyAndNeverDeploys(t *testing.T) {
	workflow := decodeWorkflow(t, ".github/workflows/site-validate.yml")
	if got := sortedKeys(workflow.On); !reflect.DeepEqual(got, []string{"pull_request", "push", "workflow_dispatch"}) {
		t.Fatalf("site validation triggers = %v, want pull_request, push, and workflow_dispatch only", got)
	}
	push, ok := workflow.On["push"].(map[string]any)
	if !ok || !reflect.DeepEqual(push["branches"], []any{"main"}) {
		t.Fatalf("site validation push trigger must be limited to main, got %v", workflow.On["push"])
	}
	if len(workflow.Permissions) != 0 {
		t.Fatalf("site validation must deny permissions by default, got %v", workflow.Permissions)
	}
	if got := sortedKeys(workflow.Jobs); !reflect.DeepEqual(got, []string{"validate"}) {
		t.Fatalf("site validation jobs = %v, want exactly validate", got)
	}
	job := workflow.Jobs["validate"]
	if !reflect.DeepEqual(job.Permissions, map[string]string{"contents": "read"}) {
		t.Fatalf("validate permissions = %v, want exactly contents: read", job.Permissions)
	}
	if job.Environment != "" || job.RunsOn != "ubuntu-24.04" {
		t.Fatalf("validate must run on ubuntu-24.04 without a deployment environment, got runs-on %q environment %q", job.RunsOn, job.Environment)
	}
	var runs []string
	checkouts := 0
	for _, step := range job.Steps {
		lower := strings.ToLower(step.Uses + "\n" + step.Run)
		for _, prohibited := range []string{"deploy-pages", "upload-pages-artifact", "configure-pages", "upload-artifact", "gh-pages", "git push", "gh release", "gh api", "curl ", "wget "} {
			if strings.Contains(lower, prohibited) {
				t.Errorf("site validation step %q must not contain %q", step.Name, prohibited)
			}
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkouts++
			if step.With["persist-credentials"] != false {
				t.Errorf("site validation checkout must not persist credentials, got %v", step.With["persist-credentials"])
			}
		}
		if step.Run != "" {
			runs = append(runs, step.Run)
		}
	}
	if checkouts != 1 {
		t.Fatalf("site validation must check out the repository exactly once, got %d", checkouts)
	}
	joined := strings.Join(runs, "\n")
	for _, required := range []string{"make sample-site-check", "make readme-candidate-check", "make sample-site-browser-audit"} {
		if !strings.Contains(joined, required) {
			t.Errorf("site validation must run %q", required)
		}
	}
	if strings.Contains(joined, "${{") {
		t.Error("site validation run steps must not interpolate workflow expressions")
	}
}
