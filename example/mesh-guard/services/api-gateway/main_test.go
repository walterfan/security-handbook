// API Gateway tests — HMAC auth, rate limiting, health check
//
// Demonstrates ch12 (API Authentication) and ch26 (API Security)

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
}

func TestComputeHMAC(t *testing.T) {
	// Known test vector
	sig := ComputeHMAC("test-message", "test-secret")
	if sig == "" {
		t.Error("HMAC should not be empty")
	}
	// Same input should produce same output
	sig2 := ComputeHMAC("test-message", "test-secret")
	if sig != sig2 {
		t.Error("HMAC should be deterministic")
	}
	// Different input should produce different output
	sig3 := ComputeHMAC("different-message", "test-secret")
	if sig == sig3 {
		t.Error("Different messages should produce different HMACs")
	}
}

func TestHMACEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "def", false},
		{"", "", true},
		{"abc", "abcd", false},
	}
	for _, tt := range tests {
		got := HMACEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("HMACEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestHMACAuthMiddleware_NoHeaders(t *testing.T) {
	// Without auth headers, should pass through (demo mode)
	handler := hmacAuthMiddleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/orders", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (demo mode), got %d", w.Code)
	}
}

func TestHMACAuthMiddleware_ValidSignature(t *testing.T) {
	secret := "test-secret"
	apiKey := "my-api-key"
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := ComputeHMAC(apiKey+timestamp, secret)

	handler := hmacAuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/orders", nil)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHMACAuthMiddleware_InvalidSignature(t *testing.T) {
	handler := hmacAuthMiddleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/orders", nil)
	req.Header.Set("X-API-Key", "my-key")
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Signature", "invalid-signature")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHMACAuthMiddleware_ExpiredTimestamp(t *testing.T) {
	secret := "test-secret"
	apiKey := "my-key"
	// Timestamp 10 minutes ago
	timestamp := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	signature := ComputeHMAC(apiKey+timestamp, secret)

	handler := hmacAuthMiddleware(secret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/orders", nil)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (expired), got %d", w.Code)
	}
}

func TestHMACAuthMiddleware_MissingHeaders(t *testing.T) {
	handler := hmacAuthMiddleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Only API key, missing timestamp and signature
	req := httptest.NewRequest("GET", "/api/orders", nil)
	req.Header.Set("X-API-Key", "my-key")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
