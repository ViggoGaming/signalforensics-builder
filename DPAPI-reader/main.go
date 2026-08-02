package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/wat4r/dpapitk/blob"
	"github.com/wat4r/dpapitk/masterkey"
	"github.com/wat4r/dpapitk/utils"
)

type Result struct {
	AuxKey string `json:"aux_key"`
}

func findUserProfile(username string) (string, error) {
	roots := []string{
		`C:\Users`,
		os.Getenv("SystemDrive") + `\Users`,
		filepath.Join(os.Getenv("USERPROFILE"), ".."),
	}
	for _, root := range roots {
		profile := filepath.Join(root, username)
		if st, err := os.Stat(profile); err == nil && st.IsDir() {
			return profile, nil
		}
	}
	return "", fmt.Errorf("user profile for '%s' not found", username)
}

func findSIDAndMasterKey(profile string) (sid, mkPath string, err error) {
	candidates := []string{
		filepath.Join(profile, "AppData", "Roaming", "Microsoft", "Protect"),
		filepath.Join(profile, "Desktop", "Protect"),
		filepath.Join(profile, "Documents", "Protect"),
	}
	for _, base := range candidates {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "S-1-5-21-") {
				sid = e.Name()
				sidDir := filepath.Join(base, sid)
				files, _ := os.ReadDir(sidDir)
				for _, f := range files {
					name := f.Name()
					if !f.IsDir() && len(name) == 36 && strings.Count(name, "-") == 4 {
						return sid, filepath.Join(sidDir, name), nil
					}
				}
			}
		}
	}
	return "", "", fmt.Errorf("no masterkey found for user profile %s", profile)
}

func findLocalState(profile string) (string, error) {
	candidates := []string{
		filepath.Join(profile, "AppData", "Roaming", "Signal", "Local State"),
		filepath.Join(profile, "Desktop", "Signal", "Local State"),
		filepath.Join(profile, "Documents", "Signal", "Local State"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("Signal Local State not found under %s", profile)
}

func extractBlob(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}
	var js struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &js); err != nil {
		return nil, err
	}
	if js.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("encrypted_key not found in Local State")
	}
	raw, err := base64.StdEncoding.DecodeString(js.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(raw) > 5 && string(raw[:5]) == "DPAPI" {
		return raw[5:], nil
	}
	return raw, nil
}

func main() {
	user := flag.String("user", "", "Windows username (e.g. prh)")
	password := flag.String("password", "", "Windows password")
	flag.Parse()

	if *user == "" || *password == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -user <username> -password <password>\n", os.Args[0])
		os.Exit(1)
	}

	profile, err := findUserProfile(*user)
	if err != nil {
		log.Fatal(err)
	}

	sid, mkPath, err := findSIDAndMasterKey(profile)
	if err != nil {
		log.Fatal(err)
	}

	localState, err := findLocalState(profile)
	if err != nil {
		log.Fatal(err)
	}

	blobData, err := extractBlob(localState)
	if err != nil {
		log.Fatal(err)
	}

	mkData := utils.ReadFile(mkPath)
	mk := masterkey.InitMasterKeyFile(mkData)
	mk.DecryptWithPassword(sid, *password)

	if !mk.Decrypted {
		log.Fatal("Failed to decrypt masterkey wrong password?")
	}

	auxKey, err := blob.DecryptWithMasterKey(blobData, mk.Key, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt auxiliary key: %v", err)
	}

	result := Result{
		AuxKey: hex.EncodeToString(auxKey),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}