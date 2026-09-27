// Package redact provides an io.Writer that masks card-number-like digit runs
// before they reach the wrapped writer.
//
// Rules and the buffering requirement are in ../PROJECT.md §3.4:
//
//   - a run of 13–19 digits is always redacted;
//   - a run of 12 digits is redacted only when it passes Luhn;
//   - shorter runs are untouched;
//   - a PAN split across two Write calls must still be redacted.
//
// TODO: implement buffering of a trailing digit run (up to 19 digits) so the
// split case works, and flush it from Close. Bytes that cannot start a digit
// run must go to the inner writer immediately.
package redact

import (
	"io"

	"example.com/pan-vault/internal/pan"
)

// Writer redacts redactable digit runs on their way to inner.
type Writer struct {
	inner  io.Writer
	buffer []byte
}

// NewWriter wraps inner. The caller must Close it to flush any buffered
// trailing digit run.

// /Question
func NewWriter(inner io.Writer) *Writer {
	return &Writer{inner: inner}
}

// Write implements io.Writer. All bytes are consumed: return len(p) once they
// are either forwarded to inner or buffered.
//
// TODO: implement.
func (w *Writer) Write(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		if p[i] >= '0' && p[i] <= '9' {
			w.buffer = append(w.buffer, p[i])
			//point
			continue
		}
		err := w.Buffer()
		if err != nil {
			return i, err
		}
		//point
		_, err = w.inner.Write([]byte{p[i]})
		if err != nil {
			return i, err
		}
	}
	//point
	return len(p), nil
}

func pointer(v string) (int, string, bool) {
	for c := 19; c >= 12; c-- {
		if c > len(v) {
			continue
		}
		for i := 0; i+c <= len(v); i++ {
			value := v[i : i+c]
			if pan.IsLuhnValid(value) {
				return i, value, true
			}
		}
	}
	return 0, "", false
}

// TODO : if pan between some numbers
func (w *Writer) Buffer() error {
	str := string(w.buffer)
	result := str

	if len(w.buffer) == 0 {
		return nil
	}
	if len(w.buffer) >= 13 && len(w.buffer) <= 19 {
		mask, err := pan.Mask(str)
		if err != nil {
			return err
		}
		result = mask
	}
	if len(w.buffer) == 12 && pan.IsLuhnValid(str) {
		mask, err := pan.Mask(str)
		if err != nil {
			return err
		}
		result = mask
	}

	if len(str) > 19 {

		s, card, ok := pointer(str)

		if ok {
			mask, err := pan.Mask(card)
			if err != nil {
				return err
			}

			result =
				str[:s] +
					mask +
					str[s+len(card):]
		}
	}

	_, err := w.inner.Write([]byte(result))
	if err != nil {
		return err
	}
	w.buffer = w.buffer[:0]
	return nil
}

// Close flushes buffered bytes to inner. It does not close inner.
//
// TODO: implement.
func (w *Writer) Close() error {
	return w.Buffer()
}
