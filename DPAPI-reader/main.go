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

func userProfile(name string) string {
	for _, root := range []string{`C:\Users`, os.Getenv("SystemDrive") + `\Users`} {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	log.Fatalf("profile not found: %s", name)
	return ""
}

func findMasterkey(profile string) (sid, path string) {
	for _, base := range []string{
		filepath.Join(profile, `AppData\Roaming\Microsoft\Protect`),
		filepath.Join(profile, "Desktop", "Protect"),
		filepath.Join(profile, "Documents", "Protect"),
	} {
		ents, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "S-1-5-21-") {
				continue
			}
			sid = e.Name()
			files, _ := os.ReadDir(filepath.Join(base, sid))
			for _, f := range files {
				n := f.Name()
				if !f.IsDir() && len(n) == 36 && strings.Count(n, "-") == 4 {
					return sid, filepath.Join(base, sid, n)
				}
			}
		}
	}
	log.Fatal("no masterkey found")
	return "", ""
}

func findLocalState(profile string) string {
	for _, p := range []string{
		filepath.Join(profile, `AppData\Roaming\Signal\Local State`),
		filepath.Join(profile, "Desktop", "Signal", "Local State"),
		filepath.Join(profile, "Documents", "Signal", "Local State"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	log.Fatal("Local State not found")
	return ""
}

func readEncryptedKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(b, &ls); err != nil {
		log.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(ls.OsCrypt.EncryptedKey)
	if err != nil {
		log.Fatal(err)
	}
	if len(raw) > 5 && string(raw[:5]) == "DPAPI" {
		raw = raw[5:]
	}
	return raw
}

func decryptAux(mkPath, sid, password string, data []byte) string {
	mk := masterkey.InitMasterKeyFile(utils.ReadFile(mkPath))
	mk.DecryptWithPassword(sid, password)
	if !mk.Decrypted {
		log.Fatal("masterkey decrypt failed (bad password?)")
	}
	key, err := blob.DecryptWithMasterKey(data, mk.Key, nil)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(key)
}

func main() {
	mode := flag.String("m", "live", "live|offline")
	user := flag.String("user", "", "")
	password := flag.String("password", "", "")
	mkPath := flag.String("masterkey", "", "")
	sidFlag := flag.String("sid", "", "")
	lsPath := flag.String("localstate", "", "")
	flag.Parse()

	if *password == "" {
		fmt.Fprintf(os.Stderr, "live:    %s -user USER -password PASS\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "offline: %s -m offline -masterkey FILE -sid SID -password PASS -localstate FILE\n", os.Args[0])
		os.Exit(1)
	}

	var sid, mk string
	var enc []byte

	switch strings.ToLower(*mode) {
	case "live":
		if *user == "" {
			log.Fatal("-user required")
		}
		prof := userProfile(*user)
		sid, mk = findMasterkey(prof)
		enc = readEncryptedKey(findLocalState(prof))
	case "offline":
		if *mkPath == "" || *sidFlag == "" || *lsPath == "" {
			log.Fatal("offline needs -masterkey, -sid, -localstate")
		}
		sid, mk = *sidFlag, *mkPath
		enc = readEncryptedKey(*lsPath)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	out, _ := json.MarshalIndent(map[string]string{"aux_key": decryptAux(mk, sid, *password, enc)}, "", "  ")
	fmt.Println(string(out))
}
