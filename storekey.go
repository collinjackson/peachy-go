package peachy

// The MLS store's key. Peachy's MLS library opens a store file only encrypted
// (SQLCipher, a 32-byte raw key); a file in the clear opens only in its test
// builds. A device keeps its key in mls.key beside the store (mode 0600, in the
// device directory that already holds its seed and account key in device.json,
// so the key guards against a stray copy of the store, not of the folder), and
// a store written in the clear by an older build is encrypted once, in place,
// on open.
//
// The encryption uses the SQLCipher compiled into the MLS library itself, so the
// file comes out exactly as the library's own open_encrypted expects.

/*
#include <stdlib.h>
typedef struct sqlite3 sqlite3;
int sqlite3_open_v2(const char *filename, sqlite3 **db, int flags, const char *vfs);
int sqlite3_exec(sqlite3 *db, const char *sql, void *callback, void *arg, char **errmsg);
int sqlite3_close(sqlite3 *db);
const char *sqlite3_errmsg(sqlite3 *db);
void sqlite3_free(void *p);
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

// ATTACH opens with the main connection's flags, so CREATE is what lets it make the encrypted file.
const (
	sqliteOpenReadWrite = 0x00000002
	sqliteOpenCreate    = 0x00000004
)

// sqliteMagic starts every SQLite file in the clear; an encrypted one starts
// with random bytes.
var sqliteMagic = []byte("SQLite format 3\x00")

// storeKey returns the device's 32-byte store key from mls.key in dir, making
// one when there is none.
func storeKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "mls.key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s holds %d bytes, not 32", path, len(b))
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// isPlaintextStore says whether path is a SQLite file in the clear.
func isPlaintextStore(path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, len(sqliteMagic))
	n, _ := f.Read(head)
	return n == len(head) && bytes.Equal(head, sqliteMagic), nil
}

// prepareStore gets the MLS store at path ready to open under key: it puts
// back a store an older build's migration left half moved, and encrypts one
// still in the clear. A device that has joined groups (existed) and has no
// store is refused rather than opened: the engine would make a new, empty
// one, and the device would silently drop out of every group it was in.
func prepareStore(path string, key []byte, existed bool) error {
	if err := recoverHalfMoved(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if existed {
			return fmt.Errorf("the MLS store %s is missing: this device's groups are in it. Restore it, or sign this device out and link it again", path)
		}
		return nil
	} else if err != nil {
		return err
	}
	plain, err := isPlaintextStore(path)
	if err != nil || !plain {
		return err
	}
	if err := encryptStore(path, key); err != nil {
		return fmt.Errorf("encrypting the MLS store: %w", err)
	}
	return nil
}

// recoverHalfMoved undoes the two-rename migration of builds before
// 2026-11-11 when it stopped between its renames: the store renamed to
// path.plain-<date>, the encrypted copy not yet renamed in. The clear copy is
// complete, so it goes back, to be encrypted again.
func recoverHalfMoved(path string) error {
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	copies, err := filepath.Glob(path + ".plain-*")
	if err != nil || len(copies) == 0 {
		return err
	}
	var newest string
	for _, c := range copies {
		if !strings.HasSuffix(c, "-wal") && !strings.HasSuffix(c, "-shm") && c > newest {
			newest = c // the names end in a UTC date, so the greatest is the newest
		}
	}
	if newest == "" {
		return nil
	}
	_ = os.Remove(path + ".encrypting")
	return os.Rename(newest, path)
}

// encryptStore rewrites the clear store at path under key: export into a new
// encrypted file beside it, flush that to disk, then rename it over the clear
// one. The rename is atomic, so a crash leaves either the clear store or the
// encrypted one at path, never neither. No clear copy is kept.
func encryptStore(path string, key []byte) error {
	tmp := path + ".encrypting"
	_ = os.Remove(tmp)
	// tmp comes from our own path: no quote in it to escape, but refuse one anyway.
	if strings.ContainsAny(tmp, "'\"") {
		return fmt.Errorf("store path %q has a quote in it", tmp)
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	// CREATE: ATTACH opens with the main connection's flags, and it makes tmp.
	if rc := C.sqlite3_open_v2(cpath, &db, sqliteOpenReadWrite|sqliteOpenCreate, nil); rc != 0 {
		if db != nil {
			C.sqlite3_close(db)
		}
		return fmt.Errorf("open %s: sqlite code %d", path, int(rc))
	}
	exec := func(sql string) error {
		csql := C.CString(sql)
		defer C.free(unsafe.Pointer(csql))
		var msg *C.char
		if rc := C.sqlite3_exec(db, csql, nil, nil, &msg); rc != 0 {
			e := C.GoString(msg)
			C.sqlite3_free(unsafe.Pointer(msg))
			return fmt.Errorf("%s: %s", sql[:min(len(sql), 40)], e)
		}
		return nil
	}
	// Everything into the main file first, so the -wal left beside it is empty.
	err := exec("PRAGMA wal_checkpoint(TRUNCATE);")
	if err == nil {
		err = exec(fmt.Sprintf(`ATTACH DATABASE '%s' AS enc KEY "x'%s'";`, tmp, hex.EncodeToString(key)))
	}
	if err == nil {
		err = exec("PRAGMA enc.cipher_plaintext_header_size = 0; SELECT sqlcipher_export('enc'); DETACH DATABASE enc;")
	}
	C.sqlite3_close(db)
	if err == nil {
		err = syncFile(tmp)
	}
	if err == nil {
		_ = os.Chmod(tmp, 0o600)
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// The clear store's -wal (empty after the checkpoint) and -shm must not
	// be read against the encrypted file.
	for _, side := range []string{"-wal", "-shm"} {
		_ = os.Remove(path + side)
	}
	return syncFile(filepath.Dir(path))
}

// removeClearCopies deletes what older builds' migrations left beside the
// store: clear copies (path.plain-<date>, which hold group secrets) and an
// unfinished encrypted export. Each copy is overwritten with zeros first,
// which helps on a disk that writes in place; on an SSD or a copy-on-write
// filesystem the old blocks may survive until reused. Returns how many files
// it removed. Call it only once the encrypted store has opened.
func removeClearCopies(path string) (int, error) {
	copies, err := filepath.Glob(path + ".plain-*")
	if err != nil {
		return 0, err
	}
	copies = append(copies, path+".encrypting")
	n := 0
	for _, c := range copies {
		fi, err := os.Stat(c)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return n, err
		}
		if err := zeroFile(c, fi.Size()); err != nil {
			return n, err
		}
		if err := os.Remove(c); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func zeroFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	zeros := make([]byte, 64*1024)
	for left := size; left > 0; {
		n := min(left, int64(len(zeros)))
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		left -= n
	}
	return f.Sync()
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// sqliteExec runs sql on the file at path (created if missing) and returns
// SQLite's result code: the tests' door to a store, keyed or not.
func sqliteExec(path, sql string) int {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	var db *C.sqlite3
	if rc := C.sqlite3_open_v2(cp, &db, sqliteOpenReadWrite|sqliteOpenCreate, nil); rc != 0 {
		return int(rc)
	}
	defer C.sqlite3_close(db)
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	return int(C.sqlite3_exec(db, cs, nil, nil, nil))
}
