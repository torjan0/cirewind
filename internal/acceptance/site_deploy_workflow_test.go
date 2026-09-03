package acceptance_test

import (
	"reflect"
	"strings"
	"testing"
)

// TestSiteDeploymentWorkflowIsExactTagAndLeastPrivilege pins the SITE-005
// contract: production deployment is dispatch-only at an existing annotated
// release tag, the build job holds contents: read only, the deploy job holds
// only the documented Pages and OIDC permissions on the protected github-pages
// environment, the artifact travels once under a trusted run-unique name, and
// the workflow never calls a local hash an uploaded-artifact digest or claims
// ID-addressed deployment.
func TestSiteDeploymentWorkflowIsExactTagAndLeastPrivilege(t *testing.T) {
	const path = ".github/workflows/site-deploy.yml"
	workflow := decodeWorkflow(t, path)
	text := string(readRepositoryFile(t, path))

	if got := sortedKeys(workflow.On); !reflect.DeepEqual(got, []string{"workflow_dispatch"}) {
		t.Fatalf("site deployment triggers = %v, want workflow_dispatch only", got)
	}
	dispatch, ok := workflow.On["workflow_dispatch"].(map[string]any)
	if !ok {
		t.Fatal("site deployment dispatch must declare inputs")
	}
	inputs, ok := dispatch["inputs"].(map[string]any)
	if !ok || len(inputs) != 1 {
		t.Fatalf("site deployment dispatch inputs = %v, want exactly tag", dispatch["inputs"])
	}
	tagInput, ok := inputs["tag"].(map[string]any)
	if !ok || tagInput["required"] != true || tagInput["type"] != "string" {
		t.Fatalf("site deployment tag input = %v, want a required string", inputs["tag"])
	}
	if len(workflow.Permissions) != 0 {
		t.Fatalf("site deployment must deny permissions by default, got %v", workflow.Permissions)
	}
	if got := sortedKeys(workflow.Jobs); !reflect.DeepEqual(got, []string{"build", "deploy"}) {
		t.Fatalf("site deployment jobs = %v, want exactly build and deploy", got)
	}

	build := workflow.Jobs["build"]
	if !reflect.DeepEqual(build.Permissions, map[string]string{"contents": "read"}) {
		t.Fatalf("build permissions = %v, want exactly contents: read", build.Permissions)
	}
	if build.Environment != nil {
		t.Fatalf("build job must not use a deployment environment, got %v", build.Environment)
	}
	if build.RunsOn != "ubuntu-24.04" {
		t.Fatalf("build job runs-on = %q", build.RunsOn)
	}
	if len(build.Steps) == 0 || build.Steps[0].Uses != "" || !strings.Contains(build.Steps[0].Run, `test "$GITHUB_REF" = "refs/tags/$SITE_TAG"`) {
		t.Fatal("build job must validate the dispatch ref before any checkout")
	}
	var checkouts, uploads int
	var runs []string
	for _, step := range build.Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkouts++
			if step.With["ref"] != "refs/tags/${{ inputs.tag }}" || step.With["persist-credentials"] != false || step.With["fetch-depth"] != 0 {
				t.Errorf("build checkout must target the exact requested tag without stored credentials, got %v", step.With)
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-pages-artifact@") {
			uploads++
			name, _ := step.With["name"].(string)
			if step.ID != "upload" || !strings.Contains(name, "${{ github.run_id }}") || !strings.Contains(name, "${{ github.run_attempt }}") {
				t.Errorf("Pages artifact must be uploaded once under a run-unique trusted name, got %v", step.With)
			}
			if p, _ := step.With["path"].(string); !strings.HasPrefix(p, "${{ runner.temp }}/") {
				t.Errorf("Pages artifact path must be the staged site under runner.temp, got %v", step.With["path"])
			}
		}
		if strings.HasPrefix(step.Uses, "actions/deploy-pages@") || strings.HasPrefix(step.Uses, "actions/configure-pages@") {
			t.Errorf("build job must not deploy or configure Pages: %s", step.Uses)
		}
		if step.Run != "" {
			runs = append(runs, step.Run)
		}
	}
	if checkouts != 1 || uploads != 1 {
		t.Fatalf("build job checkouts=%d uploads=%d, want exactly one each", checkouts, uploads)
	}
	joined := strings.Join(runs, "\n")
	for _, required := range []string{
		"./scripts/verify-release-ref.sh \"$SITE_TAG\"",
		"./scripts/verify-release-environment.sh \"$GITHUB_REPOSITORY\" github-pages \"$GITHUB_REPOSITORY_OWNER\"",
		"gh release view \"$SITE_TAG\"",
		"./scripts/build-sample-site.sh",
		"cmp site/generated/graph.svg",
		"samplesite verify",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("build job must run %q", required)
		}
	}
	if !strings.Contains(build.Outputs["artifact-name"], "steps.") || !strings.Contains(build.Outputs["artifact-id"], "steps.upload.outputs.artifact_id") {
		t.Fatalf("build outputs must expose the trusted artifact name and the returned artifact identifier, got %v", build.Outputs)
	}

	deploy := workflow.Jobs["deploy"]
	if !reflect.DeepEqual(deploy.Permissions, map[string]string{"pages": "write", "id-token": "write"}) {
		t.Fatalf("deploy permissions = %v, want exactly pages: write and id-token: write", deploy.Permissions)
	}
	environment, ok := deploy.Environment.(map[string]any)
	if !ok || environment["name"] != "github-pages" || !strings.Contains(environment["url"].(string), "steps.deployment.outputs.page_url") {
		t.Fatalf("deploy job must use the protected github-pages environment and record the deployment URL, got %v", deploy.Environment)
	}
	if needs, ok := deploy.Needs.([]any); !ok || !reflect.DeepEqual(needs, []any{"build"}) {
		t.Fatalf("deploy job must depend on the exact build job, got %v", deploy.Needs)
	}
	var deploys int
	for _, step := range deploy.Steps {
		if step.Uses != "" && !strings.HasPrefix(step.Uses, "actions/deploy-pages@") {
			t.Errorf("deploy job may use only deploy-pages, got %s", step.Uses)
		}
		if strings.HasPrefix(step.Uses, "actions/deploy-pages@") {
			deploys++
			if step.ID != "deployment" || step.With["artifact_name"] != "${{ needs.build.outputs.artifact-name }}" {
				t.Errorf("deploy-pages must receive the exact trusted artifact name from the build job, got %v", step.With)
			}
			if _, hasID := step.With["artifact_id"]; hasID {
				t.Error("deploy-pages must not claim ID-addressed deployment")
			}
		}
	}
	if deploys != 1 {
		t.Fatalf("deploy job deploys=%d, want exactly one", deploys)
	}

	for _, prohibited := range []string{"artifact digest", "uploaded-artifact digest", "pull_request", "push:", "curl ", "wget "} {
		if strings.Contains(text, prohibited) {
			t.Errorf("site deployment workflow must not contain %q", prohibited)
		}
	}
	for _, required := range []string{"not a digest", "identifier", "concurrency:", "cancel-in-progress: false"} {
		if !strings.Contains(text, required) {
			t.Errorf("site deployment workflow must state %q", required)
		}
	}
}
