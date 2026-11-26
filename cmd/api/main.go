package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/treeward-ai/treeward/internal/api"
	"github.com/treeward-ai/treeward/internal/signer"
	"github.com/treeward-ai/treeward/internal/store"
)

func main() {
	shirudoBin := flag.String("shirudo-bin", os.Getenv("SHIRUDO_BIN"), "path to shirudo binary for attestation verification (empty preserves mock behavior)")
	shirudoAKName := flag.String("shirudo-ak-name", os.Getenv("SHIRUDO_AK_NAME"), "default AK name hex for shirudo attest verify")
	shirudoExpectConfigRoot := flag.String("shirudo-expect-config-root", os.Getenv("SHIRUDO_EXPECT_CONFIG_ROOT"), "optional --expect-config-root for shirudo attest verify")
	shirudoExpectConfigPCR := flag.String("shirudo-expect-config-pcr", os.Getenv("SHIRUDO_EXPECT_CONFIG_PCR"), "optional --expect-config-pcr for shirudo attest verify")
	flag.Parse()

	addr := env("TREEWARD_ADDR", ":8080")
	bootstrap := os.Getenv("TREEWARD_BOOTSTRAP_TOKEN")
	if bootstrap == "" {
		log.Fatal("TREEWARD_BOOTSTRAP_TOKEN is required")
	}
	keyDir := env("TREEWARD_KEY_DIR", "/var/treeward/keys")
	dataDir := env("TREEWARD_DATA_DIR", "/var/treeward/data")

	sig, err := signer.NewLocal(keyDir)
	if err != nil {
		log.Fatalf("signer: %v", err)
	}
	log.Printf("local signer pubkey=%s", sig.PublicKeyHex())

	dbPath := filepath.Join(dataDir, "treeward.db")
	st, err := store.Open(dbPath, bootstrap, sig)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()
	log.Printf("sqlite store %s (connectors=%d artifacts=%d)", dbPath, len(st.Connectors), len(st.Artifacts))

	srv := api.New(st)
	if strings.EqualFold(os.Getenv("TREEWARD_AUTH"), "off") {
		srv.AuthDisabled = true
		log.Printf("WARNING: TREEWARD_AUTH=off — admin API authentication is DISABLED (local development only)")
	}
	if *shirudoBin != "" {
		srv.Verifier = api.NewShirudoVerifier(api.ShirudoVerifierConfig{
			Bin:              *shirudoBin,
			AKName:           *shirudoAKName,
			ExpectConfigRoot: *shirudoExpectConfigRoot,
			ExpectConfigPCR:  *shirudoExpectConfigPCR,
		})
		log.Printf("shirudo attest verifier enabled (bin=%s)", *shirudoBin)
	}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	tlsCert := os.Getenv("TREEWARD_TLS_CERT")
	tlsKey := os.Getenv("TREEWARD_TLS_KEY")
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatal("TREEWARD_TLS_CERT and TREEWARD_TLS_KEY must both be set to enable TLS")
	}
	if tlsCert != "" {
		httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		log.Printf("treeward api listening on %s (TLS 1.3)", addr)
		log.Fatal(httpSrv.ListenAndServeTLS(tlsCert, tlsKey))
	}

	log.Printf("treeward api listening on %s", addr)
	log.Fatal(httpSrv.ListenAndServe())
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
