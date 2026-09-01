package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/AzureOSK/sakamichi-token-extractor/backup"
	"github.com/AzureOSK/sakamichi-token-extractor/crypto/aeswrap"
	"github.com/AzureOSK/sakamichi-token-extractor/crypto/gcm"
	"github.com/AzureOSK/sakamichi-token-extractor/encoding/asn1"
	"github.com/dunhamsteve/plist"
	"golang.org/x/term"
)

const (
	toolVersion     = "0.1.0"
	targetService   = "flutter_secure_storage_service"
	targetKeyPrefix = "FC_TOKEN_KEY_"
)

var appBundles = []struct {
	Name   string
	Bundle string
}{
	{Name: "hinatazaka", Bundle: "jp.co.sonymusic.communication.keyakizaka"},
	{Name: "nogizaka", Bundle: "jp.co.sonymusic.communication.nogizaka"},
	{Name: "sakurazaka", Bundle: "jp.co.sonymusic.communication.sakurazaka"},
}

type backupSummary struct {
	Path           string
	DeviceName     string
	ProductVersion string
	Encrypted      bool
}

type manifestSummary struct {
	IsEncrypted bool
	Lockdown    struct {
		DeviceName     string
		ProductVersion string
	}
}

type keychainEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

type keychain struct {
	General []keychainEntry `plist:"genp"`
}

type asn1Entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

// The bundled ASN.1 decoder uses an uppercase SET type-name suffix to select
// the DER SET tag rather than SEQUENCE. Keep this spelling exact.
type asn1EntrySET []asn1Entry

type candidateIdentifier struct {
	Service     string `json:"service,omitempty"`
	Account     string `json:"account,omitempty"`
	AccessGroup string `json:"access_group,omitempty"`
}

type diagnostics struct {
	GeneralEntries        int                   `json:"general_entries"`
	RecordVersions        map[uint32]int        `json:"record_versions"`
	DecryptedRecords      int                   `json:"decrypted_records"`
	DecryptFailures       map[string]int        `json:"decrypt_failures"`
	DefaultServiceCount   int                   `json:"default_service_count"`
	TargetAccountCount    int                   `json:"target_account_count"`
	RefreshTokenJSONCount int                   `json:"refresh_token_json_count"`
	CandidateIdentifiers  []candidateIdentifier `json:"candidate_identifiers,omitempty"`
}

type recoveredToken struct {
	App         string
	Token       string
	Service     string
	Account     string
	AccessGroup string
}

type tokenIndexEntry struct {
	App         string `json:"app"`
	OutputFile  string `json:"output_file"`
	Service     string `json:"service,omitempty"`
	Account     string `json:"account,omitempty"`
	AccessGroup string `json:"access_group,omitempty"`
	TokenLength int    `json:"token_length"`
}

func expandUserPath(value string) (string, error) {
	if value != "~" && !strings.HasPrefix(value, "~/") && !strings.HasPrefix(value, `~\`) {
		return filepath.Abs(value)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if value == "~" {
		return home, nil
	}
	return filepath.Join(home, value[2:]), nil
}

func inspectBackup(dir string) (backupSummary, error) {
	manifestPath := filepath.Join(dir, "Manifest.plist")
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return backupSummary{}, err
	}
	defer manifestFile.Close()
	var manifest manifestSummary
	if err := plist.Unmarshal(manifestFile, &manifest); err != nil {
		return backupSummary{}, err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		resolved = dir
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return backupSummary{}, err
	}
	return backupSummary{
		Path:           filepath.Clean(resolved),
		DeviceName:     manifest.Lockdown.DeviceName,
		ProductVersion: manifest.Lockdown.ProductVersion,
		Encrypted:      manifest.IsEncrypted,
	}, nil
}

func discoverBackups(root string) ([]backupSummary, error) {
	expanded, err := expandUserPath(root)
	if err != nil {
		return nil, err
	}
	if direct, err := inspectBackup(expanded); err == nil {
		return []backupSummary{direct}, nil
	}
	entries, err := os.ReadDir(expanded)
	if err != nil {
		return nil, err
	}
	var backups []backupSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate, err := inspectBackup(filepath.Join(expanded, entry.Name()))
		if err == nil {
			backups = append(backups, candidate)
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].Path < backups[j].Path })
	return backups, nil
}

func defaultBackupRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "MobileSync", "Backup")}
	case "windows":
		var roots []string
		if appData := os.Getenv("APPDATA"); appData != "" {
			roots = append(roots, filepath.Join(appData, "Apple Computer", "MobileSync", "Backup"))
		}
		if profile := os.Getenv("USERPROFILE"); profile != "" {
			roots = append(roots, filepath.Join(profile, "Apple", "MobileSync", "Backup"))
		}
		return roots
	default:
		return nil
	}
}

func discoverDefaultBackups() []backupSummary {
	seen := make(map[string]bool)
	var backups []backupSummary
	for _, root := range defaultBackupRoots() {
		found, err := discoverBackups(root)
		if err != nil {
			continue
		}
		for _, candidate := range found {
			if !seen[candidate.Path] {
				seen[candidate.Path] = true
				backups = append(backups, candidate)
			}
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].Path < backups[j].Path })
	return backups
}

func printBackups(backups []backupSummary) {
	for _, candidate := range backups {
		encryption := "unencrypted"
		if candidate.Encrypted {
			encryption = "encrypted"
		}
		fmt.Printf("%s (iOS %s, %s)\n  %s\n", candidate.DeviceName, candidate.ProductVersion, encryption, candidate.Path)
	}
}

func selectBackup(explicitPath string) (backupSummary, error) {
	var backups []backupSummary
	var err error
	if explicitPath != "" {
		backups, err = discoverBackups(explicitPath)
	} else {
		backups = discoverDefaultBackups()
	}
	if err != nil {
		return backupSummary{}, err
	}
	switch len(backups) {
	case 0:
		return backupSummary{}, errors.New("no iPhone backups found; pass --backup with a device-backup directory")
	case 1:
		return backups[0], nil
	default:
		printBackups(backups)
		return backupSummary{}, errors.New("multiple backups found; choose one with --backup")
	}
}

func promptPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Encrypted iPhone backup password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func parseRecord(data []byte) (map[string]interface{}, error) {
	var entries asn1EntrySET
	_, parseErr := asn1.Unmarshal(data, &entries)
	record := make(map[string]interface{}, len(entries))
	for _, entry := range entries {
		record[entry.Key] = entry.Value
	}
	// Apple's records can contain newer ASN.1 fields that this older decoder
	// does not understand. Unmarshal still returns the fields decoded before
	// that point, which is how the upstream iRestore parser handles them.
	if len(record) == 0 && parseErr != nil {
		return nil, parseErr
	}
	return record, nil
}

func decryptRecord(db *backup.MobileBackup, entry keychainEntry) (map[string]interface{}, error) {
	if len(entry.Data) < 12 {
		return nil, errors.New("keychain record is too short")
	}
	version := binary.LittleEndian.Uint32(entry.Data)
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("unsupported keychain record version %d", version)
	}
	class := binary.LittleEndian.Uint32(entry.Data[4:]) & 0xf
	wrappedLength := int(binary.LittleEndian.Uint32(entry.Data[8:]))
	if wrappedLength <= 0 || 12+wrappedLength > len(entry.Data) {
		return nil, errors.New("invalid wrapped-key length")
	}
	classKey := db.Keybag.GetClassKey(class)
	if classKey == nil {
		return nil, fmt.Errorf("no backup class key for class %d", class)
	}
	recordKey := aeswrap.Unwrap(classKey, entry.Data[12:12+wrappedLength])
	if recordKey == nil {
		return nil, errors.New("unable to unwrap keychain record key")
	}
	block, err := aes.NewCipher(recordKey)
	if err != nil {
		return nil, err
	}
	aead, err := gcm.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nil, entry.Data[12+wrappedLength:], nil)
	if err != nil {
		return nil, err
	}
	if version == 2 {
		var record map[string]interface{}
		if err := plist.Unmarshal(bytes.NewReader(plain), &record); err != nil {
			return nil, err
		}
		return record, nil
	}
	return parseRecord(plain)
}

func recordText(value interface{}) string {
	switch value := value.(type) {
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return ""
	}
}

func normalizeJSONKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", ""))
}

func findRefreshToken(value interface{}) string {
	switch value := value.(type) {
	case map[string]interface{}:
		for key, child := range value {
			if normalizeJSONKey(key) == "refreshtoken" {
				if token, ok := child.(string); ok {
					return token
				}
			}
			if token := findRefreshToken(child); token != "" {
				return token
			}
		}
	case []interface{}:
		for _, child := range value {
			if token := findRefreshToken(child); token != "" {
				return token
			}
		}
	}
	return ""
}

func tokenFromRecord(record map[string]interface{}) string {
	data := recordText(record["v_Data"])
	if data == "" {
		return ""
	}
	var decoded interface{}
	if json.Unmarshal([]byte(data), &decoded) == nil {
		return findRefreshToken(decoded)
	}
	return ""
}

func targetRecord(record map[string]interface{}) bool {
	service := recordText(record["svce"])
	account := recordText(record["acct"])
	return strings.HasPrefix(account, targetKeyPrefix) ||
		(service == targetService && targetIdentifier(account, recordText(record["agrp"])))
}

func targetIdentifier(values ...string) bool {
	for _, value := range values {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "fc_token_key_") ||
			strings.Contains(lower, "smcms_token_key") ||
			strings.Contains(lower, "sonymusic") ||
			strings.Contains(lower, "keyakizaka") ||
			strings.Contains(lower, "nogizaka") ||
			strings.Contains(lower, "sakurazaka") {
			return true
		}
	}
	return false
}

func classifyApp(accessGroup string) string {
	lower := strings.ToLower(accessGroup)
	for _, app := range appBundles {
		if strings.Contains(lower, app.Bundle) {
			return app.Name
		}
	}
	return "unclassified"
}

func recordVersion(entry keychainEntry) uint32 {
	if len(entry.Data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(entry.Data)
}

func diagnosticError(err error) string {
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "unsupported keychain record version"):
		return message
	case strings.HasPrefix(message, "no backup class key"):
		return message
	case strings.Contains(message, "unwrap keychain record key"):
		return "unable to unwrap keychain record key"
	case strings.Contains(message, "message authentication failed"):
		return "AES-GCM authentication failed"
	case strings.Contains(message, "asn1"):
		return "ASN.1 decoding failed before any fields"
	default:
		return "record decryption or decoding failed"
	}
}

func writeDiagnostics(outputDir string, report diagnostics) (string, error) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", err
	}
	if err := os.Chmod(outputDir, 0700); err != nil {
		return "", err
	}
	diagnosticsPath := filepath.Join(outputDir, "diagnostics.json")
	if err := os.WriteFile(diagnosticsPath, encoded, 0600); err != nil {
		return "", err
	}
	if err := os.Chmod(diagnosticsPath, 0600); err != nil {
		return "", err
	}
	return diagnosticsPath, nil
}

func extractTokens(db *backup.MobileBackup) ([]recoveredToken, diagnostics, error) {
	for _, file := range db.Records {
		if file.Domain != "KeychainDomain" || file.Path != "keychain-backup.plist" {
			continue
		}
		data, err := db.ReadFile(file)
		if err != nil {
			return nil, diagnostics{}, err
		}
		var kc keychain
		if err := plist.Unmarshal(bytes.NewReader(data), &kc); err != nil {
			return nil, diagnostics{}, err
		}
		report := diagnostics{
			GeneralEntries:  len(kc.General),
			RecordVersions:  make(map[uint32]int),
			DecryptFailures: make(map[string]int),
		}
		var tokens []recoveredToken
		seenTokens := make(map[string]bool)
		for _, entry := range kc.General {
			report.RecordVersions[recordVersion(entry)]++
			record, err := decryptRecord(db, entry)
			if err != nil {
				report.DecryptFailures[diagnosticError(err)]++
				continue
			}
			report.DecryptedRecords++
			service := recordText(record["svce"])
			account := recordText(record["acct"])
			accessGroup := recordText(record["agrp"])
			if service == targetService {
				report.DefaultServiceCount++
			}
			if strings.HasPrefix(account, targetKeyPrefix) {
				report.TargetAccountCount++
			}
			if tokenFromRecord(record) != "" {
				report.RefreshTokenJSONCount++
			}
			if targetIdentifier(service, account, accessGroup) {
				report.CandidateIdentifiers = append(report.CandidateIdentifiers, candidateIdentifier{
					Service:     service,
					Account:     account,
					AccessGroup: accessGroup,
				})
			}
			if !targetRecord(record) {
				continue
			}
			if token := tokenFromRecord(record); token != "" {
				if seenTokens[token] {
					continue
				}
				seenTokens[token] = true
				tokens = append(tokens, recoveredToken{
					App:         classifyApp(accessGroup),
					Token:       token,
					Service:     service,
					Account:     account,
					AccessGroup: accessGroup,
				})
			}
		}
		return tokens, report, nil
	}
	return nil, diagnostics{}, errors.New("KeychainDomain/keychain-backup.plist is absent")
}

func writeRecoveredTokens(outputDir string, tokens []recoveredToken) ([]tokenIndexEntry, error) {
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(outputDir, 0700); err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	index := make([]tokenIndexEntry, 0, len(tokens))
	for _, recovered := range tokens {
		counts[recovered.App]++
		name := recovered.App
		if counts[recovered.App] > 1 {
			name = fmt.Sprintf("%s_%d", recovered.App, counts[recovered.App])
		}
		outputPath := filepath.Join(outputDir, name+"_refresh_token.txt")
		if err := os.WriteFile(outputPath, []byte(recovered.Token+"\n"), 0600); err != nil {
			return nil, err
		}
		if err := os.Chmod(outputPath, 0600); err != nil {
			return nil, err
		}
		index = append(index, tokenIndexEntry{
			App:         recovered.App,
			OutputFile:  outputPath,
			Service:     recovered.Service,
			Account:     recovered.Account,
			AccessGroup: recovered.AccessGroup,
			TokenLength: len(recovered.Token),
		})
	}
	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return nil, err
	}
	indexData = append(indexData, '\n')
	indexPath := filepath.Join(outputDir, "index.json")
	if err := os.WriteFile(indexPath, indexData, 0600); err != nil {
		return nil, err
	}
	if err := os.Chmod(indexPath, 0600); err != nil {
		return nil, err
	}
	return index, nil
}

func main() {
	var backupPath string
	var outputDir string
	var listBackups bool
	var showVersion bool
	flag.StringVar(&backupPath, "backup", "", "device-backup directory, or a directory containing device backups")
	flag.StringVar(&outputDir, "output", "", "output directory (default: a new secure temporary directory)")
	flag.BoolVar(&listBackups, "list-backups", false, "list backups in the default MobileSync location")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(flag.CommandLine.Output(), "Extract Nogizaka46, Sakurazaka46, and Hinatazaka46 Message refresh tokens")
		fmt.Fprintln(flag.CommandLine.Output(), "from an encrypted local iPhone backup owned by the user.")
		fmt.Fprintln(flag.CommandLine.Output())
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVersion {
		fmt.Println("sakamichi-token-extractor", toolVersion)
		return
	}
	if listBackups {
		var backups []backupSummary
		var err error
		if backupPath != "" {
			backups, err = discoverBackups(backupPath)
		} else {
			backups = discoverDefaultBackups()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot list backups:", err)
			os.Exit(1)
		}
		if len(backups) == 0 {
			fmt.Fprintln(os.Stderr, "No backups found.")
			os.Exit(1)
		}
		printBackups(backups)
		return
	}

	selected, err := selectBackup(backupPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot select backup:", err)
		os.Exit(1)
	}
	if !selected.Encrypted {
		fmt.Fprintln(os.Stderr, "The selected backup is not encrypted; Keychain data is unavailable.")
		os.Exit(1)
	}
	if outputDir == "" {
		outputDir, err = os.MkdirTemp("", "sakamichi-refresh-tokens-")
	} else {
		outputDir, err = expandUserPath(outputDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot prepare output directory:", err)
		os.Exit(1)
	}
	fmt.Printf("Using %s (iOS %s)\n", selected.DeviceName, selected.ProductVersion)

	db, err := backup.OpenPath(selected.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open backup:", err)
		os.Exit(1)
	}
	if !db.Manifest.IsEncrypted {
		fmt.Fprintln(os.Stderr, "The selected backup is not encrypted; its Keychain cannot be recovered this way.")
		os.Exit(1)
	}
	password, err := promptPassword()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot read password:", err)
		os.Exit(1)
	}
	if err := db.SetPassword(password); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot unlock backup (is the password correct?):", err)
		os.Exit(1)
	}
	password = ""
	if err := db.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot load decrypted backup manifest:", err)
		os.Exit(1)
	}
	tokens, report, err := extractTokens(db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot inspect backup Keychain:", err)
		os.Exit(1)
	}
	diagnosticsPath, err := writeDiagnostics(outputDir, report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot write metadata-only diagnostics:", err)
		os.Exit(1)
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "No Sakamichi refresh tokens were recovered.")
		fmt.Fprintln(os.Stderr, "Metadata-only diagnostics were written to", diagnosticsPath)
		os.Exit(2)
	}
	index, err := writeRecoveredTokens(outputDir, tokens)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot write recovered token files:", err)
		os.Exit(1)
	}
	fmt.Printf("Recovered %d distinct Sakamichi refresh token(s):\n", len(index))
	for _, item := range index {
		fmt.Printf("  %-12s %s\n", item.App, item.OutputFile)
	}
	fmt.Println("Metadata-only index and diagnostics are in", outputDir)
}
