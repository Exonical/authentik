package kerberos

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		expression string
		want       time.Duration
	}{
		{"hours=10", 10 * time.Hour},
		{"days=1;hours=2;minutes=3", 26*time.Hour + 3*time.Minute},
		{"seconds=1.5", 1500 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.expression, func(t *testing.T) {
			got, err := parseDuration(test.expression)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("parseDuration(%q) = %s, want %s", test.expression, got, test.want)
			}
		})
	}
}

func TestParseDurationRejectsInvalidExpression(t *testing.T) {
	if got, err := parseDuration(""); err != nil || got != 0 {
		t.Fatalf("parseDuration(\"\") = %s, %v; want zero, nil", got, err)
	}
	for _, expression := range []string{"hours", "nonsense=1"} {
		t.Run(expression, func(t *testing.T) {
			if _, err := parseDuration(expression); err == nil {
				t.Fatalf("parseDuration(%q) succeeded", expression)
			}
		})
	}
}
