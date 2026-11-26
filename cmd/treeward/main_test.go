package main

import (
	"testing"
)

func TestParseCreateArtifactArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantName   string
		wantType   string
		wantDigest string
		wantErr    bool
	}{
		{
			name:       "defaults when omitted",
			args:       nil,
			wantName:   "java4shell-demo",
			wantType:   "java",
			wantDigest: "",
		},
		{
			name:       "positional name only",
			args:       []string{"vuln-app-shield"},
			wantName:   "vuln-app-shield",
			wantType:   "java",
			wantDigest: "",
		},
		{
			name:       "flags after name",
			args:       []string{"vuln-app-shield", "--digest", "vuln-app-shield", "--type", "bpf"},
			wantName:   "vuln-app-shield",
			wantType:   "bpf",
			wantDigest: "vuln-app-shield",
		},
		{
			name:       "flags before name with equals syntax",
			args:       []string{"--digest=vuln-app-shield", "--type=bpf", "vuln-app-shield"},
			wantName:   "vuln-app-shield",
			wantType:   "bpf",
			wantDigest: "vuln-app-shield",
		},
		{
			name:    "missing digest value",
			args:    []string{"vuln-app-shield", "--digest"},
			wantErr: true,
		},
		{
			name:    "unknown flag",
			args:    []string{"--bogus", "x"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCreateArtifactArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Name != tc.wantName || got.Type != tc.wantType || got.Digest != tc.wantDigest {
				t.Fatalf("got {Name:%q Type:%q Digest:%q}, want {Name:%q Type:%q Digest:%q}",
					got.Name, got.Type, got.Digest, tc.wantName, tc.wantType, tc.wantDigest)
			}
		})
	}
}
