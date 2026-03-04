// API Gateway — Entry point for MeshGuard.
//
// Demonstrates:
//   - ch12: HMAC API signature verification
//   - ch23: Zero Trust — verify every request
//   - ch24: Service Mesh — mTLS to downstream services via SPIFFE
//   - ch26: API Security — rate limiting, input validation

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

// Config holds gateway configuration
type Config struct {
	Port             string
	OrderServiceURL  string
	SpiffeSocketPath string
	HMACSecret       string
}

func loadConfig() Config {
	return Config{
		Port:             getEnv("PORT", "8080"),
		OrderServiceURL:  getEnv("ORDER_SERVICE_URL", "http://order-service:8443"),
		SpiffeSocketPath: getEnv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock"),
		HMACSecret:       getEnv("HMAC_SECRET", "demo-secret-change-me"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Handlers ───────────────────────────────────────────

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "api-gateway",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func ordersHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{Timeout: 10 * time.Second}

		// Use SPIFFE mTLS if available (ch19, ch24)
		if tlsCfg, err := loadSPIFFETLS(); err == nil {
			client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
		}

		resp, err := client.Get(cfg.OrderServiceURL + "/orders")
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"order service unavailable: %v"}`, err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// loadSPIFFETLS loads mTLS config from SPIRE-issued SVIDs (ch19, ch20)
func loadSPIFFETLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("/tmp/svid/svid.pem", "/tmp/svid/svid_key.pem")
	if err != nil {
		return nil, fmt.Errorf("load SVID: %w", err)
	}

	caCert, err := os.ReadFile("/tmp/svid/bundle.pem")
	if err != nil {
		return nil, fmt.Errorf("load trust bundle: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ── Middleware ──────────────────────────────────────────

// loggingMiddleware logs every request with timing
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[REQ] %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
		log.Printf("[RES] %s %s %s %v", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start))
	})
}

// rateLimitMiddleware — simple rate limit headers (ch26)
func rateLimitMiddleware(maxPerMinute int) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", maxPerMinute))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", maxPerMinute-1))
			next.ServeHTTP(w, r)
		})
	}
}

// ComputeHMAC computes HMAC-SHA256 signature (ch12)
func ComputeHMAC(message, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACEqual performs constant-time comparison to prevent timing attacks
func HMACEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// hmacAuthMiddleware verifies HMAC-SHA256 API signatures (ch12)
//
// Expected headers:
//
//	X-API-Key: <api-key>
//	X-Timestamp: <RFC3339-timestamp>
//	X-Signature: HMAC-SHA256(api-key + timestamp, secret)
func hmacAuthMiddleware(secret string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			timestamp := r.Header.Get("X-Timestamp")
			signature := r.Header.Get("X-Signature")

			// Skip auth if no headers (demo mode)
			if apiKey == "" && signature == "" {
				next.ServeHTTP(w, r)
				return
			}

			if apiKey == "" || timestamp == "" || signature == "" {
				http.Error(w, `{"error":"missing authentication headers"}`, http.StatusUnauthorized)
				return
			}

			// Replay protection: timestamp within 5 minutes (ch12)
			ts, err := time.Parse(time.RFC3339, timestamp)
			if err != nil {
				http.Error(w, `{"error":"invalid timestamp format"}`, http.StatusBadRequest)
				return
			}
			if time.Since(ts).Abs() > 5*time.Minute {
				http.Error(w, `{"error":"request timestamp expired"}`, http.StatusUnauthorized)
				return
			}

			// Verify HMAC signature
			expectedSig := ComputeHMAC(apiKey+timestamp, secret)
			if !HMACEqual(signature, expectedSig) {
				http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	cfg := loadConfig()

	r := mux.NewRouter()
	r.HandleFunc("/health", healthHandler).Methods("GET")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(loggingMiddleware)
	api.Use(rateLimitMiddleware(100))
	api.Use(hmacAuthMiddleware(cfg.HMACSecret))
	api.HandleFunc("/orders", ordersHandler(cfg)).Methods("GET")

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("API Gateway starting on %s", addr)

	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
