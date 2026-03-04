// Payment Service — handles payment processing.
//
// Demonstrates:
//   - ch19: SPIFFE workload identity verification
//   - ch23: Zero Trust — only accept calls from authorized services
//   - ch27: Vault integration for secrets (API keys, encryption keys)

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

type PaymentRequest struct {
	OrderID string  `json:"order_id"`
	Amount  float64 `json:"amount"`
	Method  string  `json:"method"` // "card", "bank_transfer"
}

type PaymentResult struct {
	TransactionID string `json:"transaction_id"`
	OrderID       string `json:"order_id"`
	Status        string `json:"status"`
	ProcessedAt   string `json:"processed_at"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "payment-service",
	})
}

// processPaymentHandler simulates payment processing
// In production, this would call a real payment gateway using
// secrets fetched from Vault (ch27)
func processPaymentHandler(w http.ResponseWriter, r *http.Request) {
	// Verify caller identity via mTLS (ch19, ch23)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peer := r.TLS.PeerCertificates[0]
		if len(peer.URIs) > 0 {
			spiffeID := peer.URIs[0].String()
			log.Printf("Payment request from SPIFFE ID: %s", spiffeID)

			// Zero Trust: only allow order-service to call payment-service
			allowedCallers := map[string]bool{
				"spiffe://mesh-guard/order-service": true,
			}
			if !allowedCallers[spiffeID] {
				log.Printf("DENIED: unauthorized caller %s", spiffeID)
				http.Error(w, `{"error":"unauthorized caller"}`, http.StatusForbidden)
				return
			}
		}
	}

	var req PaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body for demo
		req = PaymentRequest{OrderID: "demo-order", Amount: 0, Method: "card"}
	}

	// Simulate payment processing
	// In production: fetch payment gateway API key from Vault (ch27)
	// vaultSecret := fetchFromVault("secret/data/payment/stripe-key")
	result := PaymentResult{
		TransactionID: fmt.Sprintf("txn-%d", time.Now().UnixNano()),
		OrderID:       req.OrderID,
		Status:        "success",
		ProcessedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// getPaymentStatusHandler returns payment status
func getPaymentStatusHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	txnID := vars["txn_id"]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"transaction_id": txnID,
		"status":         "success",
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8444"
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/payments/process", processPaymentHandler).Methods("POST")
	r.HandleFunc("/payments/{txn_id}", getPaymentStatusHandler).Methods("GET")

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Payment Service starting on %s", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
