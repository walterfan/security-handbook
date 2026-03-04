package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestListOrdersHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/orders", nil)
	w := httptest.NewRecorder()
	listOrdersHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result []Order
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 orders, got %d", len(result))
	}
}

func TestGetOrderHandler_Found(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/orders/{id}", getOrderHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/orders/ord-001", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var order Order
	json.NewDecoder(w.Body).Decode(&order)
	if order.ID != "ord-001" {
		t.Errorf("expected ord-001, got %s", order.ID)
	}
}

func TestGetOrderHandler_NotFound(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/orders/{id}", getOrderHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/orders/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}
