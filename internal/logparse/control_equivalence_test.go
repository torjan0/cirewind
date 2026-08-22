package logparse

import (
	"context"
	"testing"
)

func TestRunnerControlTextEquivalenceRequiresExactPayloadSequence(t *testing.T) {
	left := []byte("\ufeff2026-08-22T02:00:37.2809246Z first\n2026-08-22T02:00:37.2852305Z second\n")
	right := []byte("\ufeff2026-08-22T02:00:37.2807824Z first\r\n2026-08-22T02:00:37.2852268Z second\r\n")
	equal, err := EqualRunnerControlText(context.Background(), left, right)
	if err != nil || !equal {
		t.Fatalf("equivalent GitHub views: equal=%v err=%v", equal, err)
	}
	for _, mutation := range [][]byte{
		[]byte("2026-08-22T02:00:37Z first\n2026-08-22T02:00:38Z changed\n"),
		[]byte("2026-08-22T02:00:37Z first\n"),
		[]byte("first\nsecond\n"),
		[]byte("2026-08-22T02:00:37Z first\n2026-08-22T02:00:38Z second\n2026-08-22T02:00:39Z extra\n"),
	} {
		equal, err := EqualRunnerControlText(context.Background(), left, mutation)
		if err != nil {
			t.Fatal(err)
		}
		if equal {
			t.Fatalf("materially different records were declared equal: %q", mutation)
		}
	}
}

func TestRunnerControlTextPrefixIsDirectional(t *testing.T) {
	prefix := []byte("2026-08-22T02:00:37.1Z first\n2026-08-22T02:00:38.1Z second\n")
	body := []byte("2026-08-22T02:00:37.2Z first\n2026-08-22T02:00:38.2Z second\n2026-08-22T02:00:39Z later output\n")
	equal, err := RunnerControlTextIsPrefix(context.Background(), prefix, body)
	if err != nil || !equal {
		t.Fatalf("prefix comparison: equal=%v err=%v", equal, err)
	}
	reverse, err := RunnerControlTextIsPrefix(context.Background(), body, prefix)
	if err != nil || reverse {
		t.Fatalf("reverse prefix comparison: equal=%v err=%v", reverse, err)
	}
	changed, err := RunnerControlTextIsPrefix(context.Background(), []byte("2026-08-22T02:00:37Z other\n"), body)
	if err != nil || changed {
		t.Fatalf("changed prefix comparison: equal=%v err=%v", changed, err)
	}
}

func TestRunnerControlTextEquivalenceHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := EqualRunnerControlText(ctx, []byte("2026-08-22T02:00:37Z first\n"), []byte("2026-08-22T02:00:37Z first\n"))
	if err != context.Canceled {
		t.Fatalf("cancellation error=%v", err)
	}
}

func FuzzRunnerControlTextEquivalence(f *testing.F) {
	f.Add("2026-08-22T02:00:37Z first\n", "2026-08-22T02:00:38Z first\n")
	f.Add("untimestamped\n", "untimestamped\n")
	f.Fuzz(func(t *testing.T, left, right string) {
		if len(left) > MaxConsolidatedJobBytes || len(right) > MaxConsolidatedJobBytes {
			return
		}
		equal, _ := EqualRunnerControlText(context.Background(), []byte(left), []byte(right))
		if equal {
			forward, _ := RunnerControlTextIsPrefix(context.Background(), []byte(left), []byte(right))
			reverse, _ := RunnerControlTextIsPrefix(context.Background(), []byte(right), []byte(left))
			if !forward || !reverse {
				t.Fatal("equality did not imply bidirectional prefix equivalence")
			}
		}
	})
}
