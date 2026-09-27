package pan

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// goldenRow mirrors one line of testdata/cards.jsonl (and ../samples/cards.jsonl).
type goldenRow struct {
	PAN       string `json:"pan"`
	LuhnValid bool   `json:"luhn_valid"`
	Masked    string `json:"masked"`
}

func readGolden(t *testing.T) []goldenRow {
	t.Helper()
	f, err := os.Open("testdata/cards.jsonl")
	if err != nil {
		t.Fatalf("open golden file: %v", err)
	}
	defer f.Close()

	var rows []goldenRow
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		if len(sc.Bytes()) == 0 {
			continue
		}
		var row goldenRow
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatalf("golden line %d: %v", line, err)
		}
		rows = append(rows, row)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan golden file: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("golden file is empty")
	}
	return rows
}

func TestIsLuhnValidGoldenFromTestdata(t *testing.T) {
	for _, row := range readGolden(t) {
		t.Run(row.PAN, func(t *testing.T) {
			if got := IsLuhnValid(row.PAN); got != row.LuhnValid {
				t.Errorf("IsLuhnValid(%q) = %v, want %v", row.PAN, got, row.LuhnValid)
			}
		})
	}
}

func TestMaskGoldenFromTestdata(t *testing.T) {
	for _, row := range readGolden(t) {
		t.Run(row.PAN, func(t *testing.T) {
			got, err := Mask(row.PAN)
			if err != nil {
				t.Fatalf("Mask(%q) returned error: %v", row.PAN, err)
			}
			if got != row.Masked {
				t.Errorf("Mask(%q) = %q, want %q", row.PAN, got, row.Masked)
			}
		})
	}
}

func TestIsLuhnValidEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"single zero", "0", true},
		{"single nonzero", "7", false},
		{"letters", "4111x11111111111", false},
		{"spaces", "4111 1111 1111 1111", false},
		{"valid visa", "4111111111111111", true},
		{"invalid visa", "4111111111111112", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLuhnValid(tc.in); got != tc.want {
				t.Errorf("IsLuhnValid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestMaskRejectsBadInput(t *testing.T) {
	cases := []string{
		"",
		"12345",                // too short
		"12345678901234567890", // too long
		"4111x11111111111",     // non-digit
		"4111 1111 1111 1111",  // spaces
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := Mask(in)
			if !errors.Is(err, ErrInvalidPAN) {
				t.Fatalf("Mask(%q) error = %v, want ErrInvalidPAN", in, err)
			}
		})
	}
}

func TestMaskNeverExposesMiddleDigits(t *testing.T) {
	for _, row := range readGolden(t) {
		got, err := Mask(row.PAN)
		if err != nil {
			t.Fatalf("Mask(%q): %v", row.PAN, err)
		}
		if len(got) != len(row.PAN) {
			t.Errorf("Mask(%q) length = %d, want %d", row.PAN, len(got), len(row.PAN))
		}
		for i := 6; i < len(got)-4; i++ {
			if got[i] != '*' {
				t.Errorf("Mask(%q)[%d] = %q, want '*'", row.PAN, i, got[i])
			}
		}
	}
}

// FuzzLuhn must never panic, whatever the input. Run it with:
//
//	go test ./internal/pan -fuzz FuzzLuhn
func FuzzLuhn(f *testing.F) {
	for _, seed := range []string{"4111111111111111", "424242424242", "", "x", "378282246310005"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = IsLuhnValid(s)
	})
}
