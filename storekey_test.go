package peachy

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func seedClearStore(t *testing.T, path string) {
	t.Helper()
	if rc := sqliteExec(path, "CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB); INSERT INTO kv VALUES('a', x'0102');"); rc != 0 {
		t.Fatalf("seed: %d", rc)
	}
}

// A device that has been in groups never opens a missing store as a new,
// empty one.
func TestPrepareStoreRefusesMissingStore(t *testing.T) {
	store := filepath.Join(t.TempDir(), "mls.sqlite")
	if err := prepareStore(store, make([]byte, 32), true); err == nil {
		t.Fatal("a missing store of a device that had groups must be refused")
	}
	if err := prepareStore(store, make([]byte, 32), false); err != nil {
		t.Fatalf("a new device has no store yet: %v", err)
	}
}

// An older build's migration that stopped between its renames left the
// store as mls.sqlite.plain-<date> and nothing at mls.sqlite: it goes back,
// encrypted, and the copies go.
func TestPrepareStoreRecoversHalfMovedMigration(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "mls.sqlite")
	seedClearStore(t, store)
	older := store + ".plain-20261110T000000"
	newest := store + ".plain-20261111T220000"
	if err := os.Rename(store, newest); err != nil {
		t.Fatal(err)
	}
	if rc := sqliteExec(older, "CREATE TABLE stale(x);"); rc != 0 {
		t.Fatal(rc)
	}
	if err := os.WriteFile(store+".encrypting", []byte("half an export"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := storeKey(dir)
	if err := prepareStore(store, key, true); err != nil {
		t.Fatal(err)
	}
	if plain, _ := isPlaintextStore(store); plain {
		t.Fatal("recovered store not encrypted")
	}
	keyed := fmt.Sprintf(`PRAGMA key = "x'%s'"; PRAGMA cipher_plaintext_header_size = 0; `, hex.EncodeToString(key))
	if rc := sqliteExec(store, keyed+"CREATE TEMP TABLE c(n INTEGER CHECK (n = 1)); INSERT INTO c SELECT count(*) FROM kv WHERE k = 'a';"); rc != 0 {
		t.Fatalf("the newest clear copy should have come back (%d)", rc)
	}
	n, err := removeClearCopies(store)
	if err != nil || n != 1 {
		t.Fatalf("removeClearCopies = %d, %v; want the older copy removed", n, err)
	}
	if left, _ := filepath.Glob(store + ".*"); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

func sqlExec(t *testing.T, path, sql string) int {
	t.Helper()
	return sqliteExec(path, sql)
}

func TestEncryptStoreInPlace(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "mls.sqlite")
	if rc := sqlExec(t, store, "PRAGMA journal_mode=WAL; CREATE TABLE kv(k TEXT PRIMARY KEY, v BLOB); INSERT INTO kv VALUES('a', x'0102');"); rc != 0 {
		t.Fatalf("seed: %d", rc)
	}
	if plain, _ := isPlaintextStore(store); !plain {
		t.Fatal("seeded store should be in the clear")
	}
	key, err := storeKey(dir)
	if err != nil || len(key) != 32 {
		t.Fatalf("storeKey: %v", err)
	}
	if again, _ := storeKey(dir); hex.EncodeToString(again) != hex.EncodeToString(key) {
		t.Fatal("storeKey must return the saved key")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "mls.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mls.key mode %v", fi.Mode().Perm())
	}
	if err := prepareStore(store, key, true); err != nil {
		t.Fatal(err)
	}
	if plain, _ := isPlaintextStore(store); plain {
		t.Fatal("store still in the clear")
	}
	left, _ := filepath.Glob(store + "*")
	if len(left) != 1 {
		t.Fatalf("migration left %v beside the store; want only the store", left)
	}
	// The library keys a store with a raw-key pragma; the row must read back under it.
	keyed := fmt.Sprintf(`PRAGMA key = "x'%s'"; PRAGMA cipher_plaintext_header_size = 0; `, hex.EncodeToString(key))
	if rc := sqlExec(t, store, keyed+"CREATE TEMP TABLE c(n INTEGER CHECK (n = 1)); INSERT INTO c SELECT count(*) FROM kv WHERE k = 'a' AND v = x'0102';"); rc != 0 {
		t.Fatalf("encrypted store does not open under the key (%d)", rc)
	}
	if rc := sqlExec(t, store, "SELECT count(*) FROM sqlite_master;"); rc == 0 {
		t.Fatal("encrypted store opened with no key")
	}
}
