// Order Service — handles order operations.
//
// Demonstrates:
//   - ch19: SPIFFE workload identity (X.509-SVID)
//   - ch23: Zero Trust — mTLS for all service-to-service calls
//   - ch24: Service Mesh — Envoy sidecar for TLS termination

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

type Order struct {
	ID        string  `json:"id"`
	Item      string  `json:"item"`
	Amount    float64 `json:"amount"`
	Status    string  `json:"status"`
	CreatedAt string  `json:"created_at"`
}

// Mock orders database
var orders = []Order{
	{ID: "ord-001", Item: "Security Handbook", Amount: 59.99, Status: "confirmed", CreatedAt: "2026-03-01T10:00:00Z"},
	{ID: "ord-002", Item: "TLS Certificate", Amount: 0.00, Status: "pending", CreatedAt: "2026-03-02T14:30:00Z"},
	{ID: "ord-003", Item: "HSM Module", Amount: 2499.00, Status: "shipped", CreatedAt: "2026-03-03T09:15:00Z"},
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "order-service",
	})
}

func listOrdersHandler(w http.ResponseWriter, r *http.Request) {
	// Log the caller's identity from mTLS (ch19: SPIFFE ID)
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peer := r.TLS.PeerCertificates[0]
		if len(peer.URIs) > 0 {
			log.Printf("Caller SPIFFE ID: %s", peer.URIs[0].String())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

func getOrderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["id"]

	for _, o := range orders {
		if o.ID == orderID {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(o)
			return
		}
	}

	http.Error(w, `{"error":"order not found"}`, http.StatusNotFound)
}

func processPaymentHandler(paymentURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		orderID := vars["id"]

		// Call payment service via mTLS (ch23: zero trust)
		client := &http.Client{Timeout: 10 * time.Second}
		if tlsCfg, err := loadSPIFFETLS(); err == nil {
			client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}

		resp, err := client.Post(
			fmt.Sprintf("%s/payments/process", paymentURL),
			"application/json",
			nil,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"payment service unavailable: %v"}`, err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"order_id": orderID,
			"payment":  "initiated",
		})
	}
}

func loadSPIFFETLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("/tmp/svid/svid.pem", "/tmp/svid/svid_key.pem")
	if err != nil {
		return nil, err
	}
	caCert, err := os.ReadFile("/tmp/svid/bundle.pem")
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	paymentURL := os.Getenv("PAYMENT_SERVICE_URL")
	if paymentURL == "" {
		paymentURL = "http://payment-service:8444"
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/orders", listOrdersHandler).Methods("GET")
	r.HandleFunc("/orders/{id}", getOrderHandler).Methods("GET")
	r.HandleFunc("/orders/{id}/pay", processPaymentHandler(paymentURL)).Methods("POST")

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Order Service starting on %s", addr)

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
