package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

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
	bootstrap := env("TREEWARD_BOOTSTRAP_TOKEN", "dev-bootstrap")
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
	if *shirudoBin != "" {
		srv.Verifier = api.NewShirudoVerifier(api.ShirudoVerifierConfig{
			Bin:              *shirudoBin,
			AKName:           *shirudoAKName,
			ExpectConfigRoot: *shirudoExpectConfigRoot,
			ExpectConfigPCR:  *shirudoExpectConfigPCR,
		})
		log.Printf("shirudo attest verifier enabled (bin=%s)", *shirudoBin)
	}
	log.Printf("treeward api listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, srv.Mux))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
