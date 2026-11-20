package peachy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fixture is Peachy's cross-client attachment fixture, from a Peachy checkout
// beside this repo (or $PEACHY_FIXTURE). It isn't ours to copy in, so without
// it these tests skip.
func fixture(t *testing.T) map[string]any {
	t.Helper()
	path := os.Getenv("PEACHY_FIXTURE")
	if path == "" {
		path = filepath.Join(protocolDir(), "mls", "fixtures", "formats", "chunking.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no Peachy fixture at %s", path)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var f map[string]any
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func list(v any) []map[string]any {
	var out []map[string]any
	for _, x := range v.([]any) {
		out = append(out, x.(map[string]any))
	}
	return out
}

func num(t *testing.T, v any) int64 {
	t.Helper()
	var s string
	switch x := v.(type) {
	case json.Number:
		s = x.String()
	case string:
		s = x
	default:
		t.Fatalf("not a number: %v", v)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func b64(t *testing.T, v any) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func prefix4(t *testing.T, v any) (p [noncePrefixBytes]byte) {
	copy(p[:], b64(t, v))
	return
}

func fixturePlaintext(size int64) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte((int64(i)*7 + 13) % 251)
	}
	return out
}

func TestSizeRules(t *testing.T) {
	f := fixture(t)
	for _, c := range list(f["chunkSize"]) {
		size, cs := num(t, c["plaintextSize"]), num(t, c["chunkSize"])
		if got := chunkSizeFor(size); got != cs {
			t.Errorf("chunk size for %d: %d, want %d", size, got, cs)
		}
		if got := chunkCountFor(size, cs); got != num(t, c["chunkCount"]) {
			t.Errorf("chunk count for %d: %d", size, got)
		}
		if got := objectSizeFor(size, cs); got != num(t, c["objectSize"]) {
			t.Errorf("object size for %d: %d", size, got)
		}
	}
	for _, c := range list(f["paddedSize"]) {
		size, padded := num(t, c["plaintextSize"]), num(t, c["paddedSize"])
		if got := paddedSizeFor(size); got != padded {
			t.Errorf("padded size for %d: %d, want %d", size, got, padded)
		}
		if got := chunkSizeFor(padded); got != num(t, c["chunkSize"]) {
			t.Errorf("padded chunk size for %d: %d", size, got)
		}
		if got := objectSizeFor(padded, chunkSizeFor(padded)); got != num(t, c["objectSize"]) {
			t.Errorf("padded object size for %d: %d", size, got)
		}
	}
}

func TestVectors(t *testing.T) {
	for _, v := range list(fixture(t)["vectors"]) {
		name, size := v["name"].(string), num(t, v["plaintextSize"])
		p := fixturePlaintext(size)
		s, err := sealChunked(p, size, b64(t, v["key"]), prefix4(t, v["noncePrefix"]), num(t, v["chunkSize"]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s.object, b64(t, v["object"])) {
			t.Errorf("%s: object differs", name)
		}
		if !bytes.Equal(s.digest[:], b64(t, v["digest"])) {
			t.Errorf("%s: digest differs", name)
		}
		got, err := openChunked(s.object, b64(t, v["key"]), b64(t, v["digest"]), -1)
		if err != nil || !bytes.Equal(got, p) {
			t.Errorf("%s: open: %v", name, err)
		}
	}
}

func TestPaddedVectors(t *testing.T) {
	f := fixture(t)
	for _, v := range list(f["paddedVectors"]) {
		name, size := v["name"].(string), num(t, v["plaintextSize"])
		p := fixturePlaintext(size)
		s, err := sealChunked(p, num(t, v["paddedSize"]), b64(t, v["key"]), prefix4(t, v["noncePrefix"]), num(t, v["chunkSize"]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(s.object, b64(t, v["object"])) {
			t.Errorf("%s: object differs", name)
		}
		got, err := openChunked(s.object, b64(t, v["key"]), b64(t, v["digest"]), size)
		if err != nil || !bytes.Equal(got, p) {
			t.Errorf("%s: open: %v", name, err)
		}
	}
	for _, c := range list(f["paddedTamper"]) {
		_, err := openChunked(b64(t, c["object"]), b64(t, c["key"]), b64(t, c["digest"]), num(t, c["size"]))
		if !unreadable(err) {
			t.Errorf("%s: got %v", c["name"], err)
		}
	}
}

func unreadable(err error) bool {
	return errors.Is(err, errUndecryptable) || errors.Is(err, errIncomplete) || errors.Is(err, errNotTheOne)
}

func TestTamperingIsRefused(t *testing.T) {
	f := fixture(t)
	vectors := map[string]map[string]any{}
	for _, v := range list(f["vectors"]) {
		vectors[v["name"].(string)] = v
	}
	for _, c := range list(f["tamper"]) {
		v := vectors[c["vector"].(string)]
		obj := b64(t, v["object"])
		m := c["mutation"].(map[string]any)
		cs, size := num(t, v["chunkSize"]), num(t, v["plaintextSize"])
		span := func(i int64) (int, int) {
			start := headerBytes + i*(cs+tagBytes)
			return int(start), int(start + chunkLen(size, cs, i) + tagBytes)
		}
		switch m["kind"] {
		case "flipByte":
			obj[num(t, m["at"])] ^= 0xff
		case "setByte":
			obj[num(t, m["at"])] = byte(num(t, m["value"]))
		case "setU32":
			binary.BigEndian.PutUint32(obj[num(t, m["at"]):], uint32(num(t, m["value"])))
		case "truncate":
			obj = obj[:num(t, m["bytes"])]
		case "dropChunk":
			s, e := span(num(t, m["index"]))
			obj = append(obj[:s:s], obj[e:]...)
		case "swapChunks":
			as, ae := span(num(t, m["a"]))
			bs, be := span(num(t, m["b"]))
			a, b := append([]byte(nil), obj[as:ae]...), append([]byte(nil), obj[bs:be]...)
			if len(a) != len(b) {
				t.Fatalf("%s: swap needs equal chunks", c["name"])
			}
			copy(obj[as:], b)
			copy(obj[bs:], a)
		default:
			t.Fatalf("unknown mutation %v", m["kind"])
		}
		_, err := openChunked(obj, b64(t, v["key"]), b64(t, v["digest"]), -1)
		var tooNew errTooNew
		ok := map[string]bool{
			"notPsa2":    errors.Is(err, errNotPSA2),
			"tooNew":     errors.As(err, &tooNew),
			"unreadable": unreadable(err),
		}[c["expect"].(string)]
		if !ok {
			t.Errorf("%s: expected %s, got %v", c["name"], c["expect"], err)
		}
	}
}

func TestRoundTripThroughAPointer(t *testing.T) {
	for _, size := range []int{0, 2, 70_000, 300_000} {
		p := fixturePlaintext(int64(size))
		s, err := sealPadded(p)
		if err != nil {
			t.Fatal(err)
		}
		ptr := pointerFor(s, "sealed/x.bin", len(p), Media{Mime: "image/jpeg", FileName: "a.jpg"})
		j, _ := json.Marshal(ptr)
		var back Attachment
		if err := json.Unmarshal(j, &back); err != nil {
			t.Fatal(err)
		}
		got, err := back.open(s.object)
		if err != nil || !bytes.Equal(got, p) {
			t.Errorf("size %d: %v", size, err)
		}
	}
}
