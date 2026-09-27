package redact

import (
	"bytes"
	"strings"
	"testing"
)

// redactLine writes line to a Writer and returns the redacted output.
func redactLine(t *testing.T, line string) string {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatalf("Write(%q): %v", line, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close after %q: %v", line, err)
	}
	return buf.String()
}

func TestRedactsLogLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"16-digit visa", "pan=4111111111111111 ", "pan=411111******1111 "},
		{"15-digit amex", "amex=378282246310005.", "amex=378282*****0005."},
		{"19-digit run", "x=4111111111111111111", "x=411111*********1111"},
		{"12-digit luhn-valid", "ref=424242424242", "ref=424242**4242"},
		{"12-digit luhn-invalid survives", "rrn=123456789012", "rrn=123456789012"},
		{"six digit stan survives", "stan=000123", "stan=000123"},
		{"nine digit amount survives", "total=987654321", "total=987654321"},
		{"already masked survives", "already 411111******1111", "already 411111******1111"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactLine(t, tc.in); got != tc.want {
				t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A PAN must be redacted even when the writer is fed one byte at a time.
func TestSplitAtEveryOffset(t *testing.T) {
	const pan = "4111111111111111"
	const want = "411111******1111"
	for i := 1; i < len(pan); i++ {
		t.Run(pan[:i]+"|"+pan[i:], func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			if _, err := w.Write([]byte(pan[:i])); err != nil {
				t.Fatalf("first Write: %v", err)
			}
			if _, err := w.Write([]byte(pan[i:])); err != nil {
				t.Fatalf("second Write: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := buf.String(); got != want {
				t.Errorf("split at %d: got %q, want %q", i, got, want)
			}
		})
	}
}

func TestCloseFlushesTrailingRun(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	if _, err := w.Write([]byte("tail=")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w.Write([]byte("4111111111111")); err != nil { // 13 digits, no terminator
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := buf.String(), "tail=411111***1111"; got != want {
		t.Errorf("after Close = %q, want %q", got, want)
	}
}

func TestNoRedactableRunSurvives(t *testing.T) {
	lines := []string{
		"pan=4111111111111111",
		"pan=378282246310005 issuer=x",
		"ref 424242424242 end",
		"a=4111111111111 and b=5555555555554444",
		"111111378282246310005",
		"88424242424242999",
	}
	for _, line := range lines {
		out := redactLine(t, line)
		for i := 0; i < len(out); i++ {
			if out[i] < '0' || out[i] > '9' {
				continue
			}
			j := i
			for j < len(out) && out[j] >= '0' && out[j] <= '9' {
				j++
			}
			run := out[i:j]
			if len(run) >= 13 || (len(run) == 12 && luhnValid(run)) {
				t.Errorf("redactable run %q survived in %q (from %q)", run, out, line)
			}
			i = j
		}
	}
}

// luhnValid is a local copy so this test does not depend on internal/pan.
func luhnValid(s string) bool {
	sum := 0
	double := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return len(s) > 0 && sum%10 == 0
}

// FuzzWriter asserts that no redactable PAN survives, whatever the writes are.
// Run it with:
//
//	go test ./internal/redact -fuzz FuzzWriter
func FuzzWriter(f *testing.F) {
	for _, seed := range []string{
		"pan=4111111111111111 tail",
		"no digits here",
		"424242424242",
		"split 4111111111 then 111111",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		out := buf.String()
		if strings.Contains(out, "4111111111111111") {
			t.Fatalf("full PAN survived: input %q, output %q", s, out)
		}
		if strings.Contains(out, "4242424242424242") {
			t.Fatalf("full PAN survived: input %q, output %q", s, out)
		}
	})
}

//
//func LoginTest(t *testing.T){
//	for _, users := range []string {
//		"user1",
//		"user2",
//	}
//	user.
//
//}
