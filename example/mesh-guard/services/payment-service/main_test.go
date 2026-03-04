package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestProcessPaymentHandler_EmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/payments/process", nil)
	w := httptest.NewRecorder()
	processPaymentHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result PaymentResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if result.TransactionID == "" {
		t.Error("transaction ID should not be empty")
	}
}

func TestProcessPaymentHandler_WithBody(t *testing.T) {
	body := `{"order_id":"ord-001","amount":59.99,"method":"card"}`
	req := httptest.NewRequest("POST", "/payments/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	processPaymentHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result PaymentResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.OrderID != "ord-001" {
		t.Errorf("expected ord-001, got %s", result.OrderID)
	}
}

func TestGetPaymentStatusHandler(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/payments/{txn_id}", getPaymentStatusHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/payments/txn-12345", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["transaction_id"] != "txn-12345" {
		t.Errorf("expected txn-12345, got %s", result["transaction_id"])
	}
}
