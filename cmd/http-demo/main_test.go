package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://demo.example/hello/world?value=1", nil)
	response := httptest.NewRecorder()

	demoHandler("example-demo").ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	want := "portalite virtual HTTP server\nidentity=example-demo\nmethod=POST\npath=/hello/world\n"
	if response.Body.String() != want {
		t.Fatalf("body = %q, want %q", response.Body.String(), want)
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --help exit = %d", code)
	}
	if stdout.String() != usageLine {
		t.Fatalf("stdout = %q, want %q", stdout.String(), usageLine)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRejectsUnexpectedArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run unexpected exit = %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, `unexpected argument "unexpected"`) || !strings.Contains(got, usageLine) {
		t.Fatalf("stderr = %q", got)
	}
}
