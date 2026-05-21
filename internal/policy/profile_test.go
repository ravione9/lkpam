package policy

import (
	"testing"
)

func TestRequesterMatches(t *testing.T) {
	if !requesterMatches(nil, []int64{1}) {
		t.Fatal("empty requester groups should match any user")
	}
	if !requesterMatches([]int64{2}, []int64{1, 2}) {
		t.Fatal("should match overlapping group")
	}
	if requesterMatches([]int64{3}, []int64{1, 2}) {
		t.Fatal("should not match when no overlap")
	}
}

func TestBuildHintsNoPolicies(t *testing.T) {
	hints := buildHints("user", []string{"user"}, nil, nil, nil)
	if len(hints) == 0 {
		t.Fatal("expected hint when no policies")
	}
}
