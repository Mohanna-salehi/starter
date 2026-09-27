package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"example.com/pan-vault/internal/vault"
	_ "github.com/joho/godotenv/autoload"
	"github.com/labstack/echo/v4"
)

var token string
var testApp = newtestApp()

// testApp builds an isolated app with a real (empty) vault and discarded logs.
func newtestApp() *echo.Echo {

	e, err := New(Deps{
		Vault:     vault.NewRedis("localhost:6379"),
		LogOutput: io.Discard,
	})
	if err != nil {
		panic(err)
	}
	return e
}

type RequestOp func(r *http.Request)

// do runs one request against e and returns the recorder.
func do(t *testing.T, e *echo.Echo, method, path, body string, ops ...RequestOp) *httptest.ResponseRecorder {
	t.Helper()
	return dohttp(e, method, path, body, ops...)
}
func TestMain(t *testing.M) {
	err := login()
	if err != nil {
		panic(err)
	}
	ev := t.Run()
	os.Exit(ev)
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON: %v (body=%q)", err, rec.Body.String())
	}
	return m
}

func TestHealth(t *testing.T) {
	rec := do(t, testApp, http.MethodGet, "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("GET /healthz body = %q", rec.Body.String())
	}
}

func TestHandleLogin(t *testing.T) {
	e := testApp
	rec := do(t, e, http.MethodPost, "/v1/login", `{"username":"user","password":"password"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if got, _ := decodeBody(t, rec)["status"].(string); got != "ok" {
		t.Errorf("login = %q, want %q", got, "ok")
	}
	if got, ok := decodeBody(t, rec)["token"].(string); !ok || got == "" {
		t.Errorf("token is empty")
	}

}

// Echo's logger must be redaction-safe by construction: New wraps the injected
// output in internal/redact.
func TestEchoLoggerOutputIsRedacted(t *testing.T) {
	var buf bytes.Buffer
	e, _ := New(Deps{Vault: vault.NewMemory(), LogOutput: &buf})

	if _, err := io.WriteString(e.Logger.Output(), "card=4111111111111111\n"); err != nil {
		t.Fatalf("write to logger output: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "4111111111111111") {
		t.Errorf("logger leaked full PAN: %q", out)
	}
	if !strings.Contains(out, "411111******1111") {
		t.Errorf("logger did not redact PAN: %q", out)
	}
}
func TestTokenizeValidPAN(t *testing.T) {
	rec := do(
		t,
		testApp,
		http.MethodPost,
		"/v1/tokenize",
		`{"pan":"4111111111111111"}`,

		func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
		},
	)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"tokenize valid = %d (%s), want 200",
			rec.Code,
			rec.Body.String(),
		)
	}

	body := decodeBody(t, rec)

	vaultToken, ok := body["token"].(string)

	if !ok || vaultToken == "" {
		t.Fatal("tokenize returned empty token")
	}

	if len(vaultToken) != 32 {
		t.Errorf(
			"token = %q, want 32 hex chars",
			vaultToken,
		)
	}

	masked, ok := body["masked"].(string)
	if !ok {
		t.Fatal("masked field is missing")
	}

	if masked != "411111******1111" {
		t.Errorf(
			"masked = %q, want %q",
			masked,
			"411111******1111",
		)
	}
}
func TestTokenizeInvalidPANReturns400(t *testing.T) {
	rec := do(t, testApp, http.MethodPost, "/v1/tokenize", `{"pan":"4111111111111112"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tokenize invalid =  %d (%s) want 400", rec.Code, rec.Body.String())
	}
	if got, _ := decodeBody(t, rec)["error_code"].(string); got != "VALIDATION_ERROR" {
		t.Errorf("error_code = %q, want VALIDATION_ERROR", got)
	}
}

func TestMaskValidPAN(t *testing.T) {
	rec := do(t, testApp, http.MethodPost, "/v1/mask", `{"pan":"424242424242"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("mask = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if got, _ := decodeBody(t, rec)["masked"].(string); got != "424242**4242" {
		t.Errorf("masked = %q, want %q", got, "424242**4242")
	}
}

func TestTokenizeDetokenizeRoundTrip(t *testing.T) {
	rec := do(t, testApp, http.MethodPost, "/v1/tokenize", `{"pan":"4111111111111111"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("tokenize = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	panToken, _ := decodeBody(t, rec)["token"].(string)
	if panToken == "" {
		t.Fatal("tokenize returned no token")
	}

	rec = do(t, testApp, http.MethodPost, "/v1/detokenize", `{"token":"`+panToken+`"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("detokenize = %d (%s), want 200", rec.Code, rec.Body.String())
	}
	if got, _ := decodeBody(t, rec)["pan"].(string); got != "4111111111111111" {
		t.Errorf("detokenized pan = %q, want %q", got, "4111111111111111")
	}
}

func TestDetokenizeUnknownReturns404(t *testing.T) {
	rec := do(t, testApp, http.MethodPost, "/v1/detokenize", `{"token":"ffffffffffffffffffffffffffffffff"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("detokenize unknown = %d, want 404", rec.Code)
	}
	if got, _ := decodeBody(t, rec)["error_code"].(string); got != "TOKEN_NOT_FOUND" {
		t.Errorf("error_code = %q, want TOKEN_NOT_FOUND", got)
	}
}

func TestAuditReturnsArray(t *testing.T) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	req.Username = "admin"
	req.Password = "admin"

	e := testApp

	do(t, e, http.MethodPost, "/v1/mask", `{"pan":"424242424242"}`, func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+token)
	})

	rec := do(t, e, http.MethodGet, "/v1/audit", "", func(r *http.Request) {
		r.SetBasicAuth(req.Username, req.Password)
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit = %d, want 200", rec.Code)
	}

	var arr []map[string]any

	if err := json.Unmarshal(rec.Body.Bytes(), &arr); err != nil {
		t.Fatalf(
			"audit is not a JSON array: %v (body=%q)",
			err,
			rec.Body.String(),
		)
	}

	if len(arr) != 0 && arr[0]["action"] == nil {
		t.Errorf("audit entry missing action: %v", arr[0])
	}
}

func TestNoFullPANInResponses(t *testing.T) {
	const pan = "4111111111111111"
	e := testApp
	responses := []string{
		do(t, e, http.MethodPost, "/v1/tokenize", `{"pan":"`+pan+`"}`).Body.String(),
		do(t, e, http.MethodPost, "/v1/mask", `{"pan":"`+pan+`"}`).Body.String(),
		do(t, e, http.MethodGet, "/v1/audit", "").Body.String(),
	}
	for i, body := range responses {
		if strings.Contains(body, pan) {
			t.Errorf("response %d leaks full PAN: %s", i, body)
		}
	}
}

func dohttp(e *echo.Echo, method, path, body string, ops ...RequestOp) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	for _, op := range ops {
		op(r)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)
	return rec
}

func login() error {
	rec := dohttp(testApp, http.MethodPost, "/v1/login", `{"username":"user","password":"password"}`)
	if rec.Code != http.StatusOK {
		return fmt.Errorf("login = %d, want 200", rec.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		return err
	}
	if got, _ := m["status"].(string); got != "ok" {
		return fmt.Errorf("status = %q, want ok", got)
	}
	var ok bool
	if token, ok = m["token"].(string); !ok || token == "" {
		return fmt.Errorf("token = %q", m["token"].(string))
	}
	return nil
}
