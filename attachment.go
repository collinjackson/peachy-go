package peachy

// Sealed attachments: the file a message's pointer names, encrypted.
//
// Three formats, told apart by the pointer's `v`:
//
//   - v1: one AES-256-GCM seal of the whole file under the pointer's nonce.
//   - v2: a "PSA2" object: a 32-byte header, then the file in chunks, each
//     sealed on its own with a nonce and associated data derived from the
//     header and the chunk's index, so chunks can't be reordered, dropped or
//     spliced.
//   - v3: a v2 object of the file padded with zeros to a size bucket; the true
//     size travels in the pointer. What current clients send, and what the
//     bridge sends.
//
// Every version carries a SHA-256 of the file, checked after opening.
// Byte-compatible with Peachy's clients: tested against their shared fixture
// (attachment_test.go).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	psa2Version      = 2
	headerBytes      = 32
	tagBytes         = 16
	noncePrefixBytes = 4
	chunkMin         = 64 * 1024
	chunkMax         = 2 * 1024 * 1024
	targetChunks     = 256
	chunkGrain       = 64 * 1024
	padFloor         = 541
	// MaxAttachmentBytes is the largest file Peachy seals, and so the largest
	// the bridge sends.
	MaxAttachmentBytes = 90 * 1024 * 1024
)

var psa2Magic = []byte("PSA2")

var (
	errNotPSA2       = errors.New("not a sealed attachment")
	errUndecryptable = errors.New("this attachment would not decrypt")
	errIncomplete    = errors.New("this attachment is missing part of itself")
	errNotTheOne     = errors.New("this attachment is not the one that was sent")
)

// errTooNew is a PSA2 object of a later format than this bridge reads.
type errTooNew uint8

func (e errTooNew) Error() string {
	return fmt.Sprintf("attachment format %d is newer than this bridge", uint8(e))
}

// Attachment is a message's pointer to one sealed file, as it travels in the
// message's `a` list.
type Attachment struct {
	ObjectKey  string `json:"o"`
	Key        string `json:"k"`
	Nonce      string `json:"n"`
	Digest     string `json:"d"`
	Size       int64  `json:"s"`
	Mime       string `json:"m"`
	Width      int    `json:"w"`
	Height     int    `json:"h"`
	DurationMS int64  `json:"ms"`
	Color      string `json:"c"`
	FileName   string `json:"f"`
	Version    int    `json:"v,omitempty"`
	ChunkSize  int    `json:"cs,omitempty"`
}

func chunkSizeFor(size int64) int64 {
	switch {
	case size <= targetChunks*chunkMin:
		return chunkMin
	case size >= targetChunks*chunkMax:
		return chunkMax
	}
	return ceilDiv(ceilDiv(size, targetChunks), chunkGrain) * chunkGrain
}

func chunkCountFor(size, chunkSize int64) int64 {
	if size == 0 {
		return 1
	}
	return ceilDiv(size, chunkSize)
}

// paddedSizeFor is the bucket a file of size bytes is padded to: 541, then up
// 5% at a time.
func paddedSizeFor(size int64) int64 {
	bucket := int64(padFloor)
	for bucket < size {
		bucket += ceilDiv(bucket, 20)
	}
	return bucket
}

func objectSizeFor(size, chunkSize int64) int64 {
	return headerBytes + size + tagBytes*chunkCountFor(size, chunkSize)
}

func chunkLen(size, chunkSize, index int64) int64 {
	if size == 0 {
		return 0
	}
	return min(chunkSize, size-index*chunkSize)
}

func ceilDiv(a, b int64) int64 { return (a + b - 1) / b }

type psa2Header struct {
	chunkSize, plaintextSize, chunkCount int64
	noncePrefix                          [noncePrefixBytes]byte
}

func (h psa2Header) bytes() []byte {
	out := make([]byte, headerBytes)
	copy(out, psa2Magic)
	out[4] = psa2Version
	binary.BigEndian.PutUint32(out[8:], uint32(h.chunkSize))
	binary.BigEndian.PutUint64(out[12:], uint64(h.plaintextSize))
	binary.BigEndian.PutUint32(out[20:], uint32(h.chunkCount))
	copy(out[24:], h.noncePrefix[:])
	return out
}

func readHeader(b []byte) (psa2Header, error) {
	if len(b) < headerBytes || !bytes.Equal(b[:4], psa2Magic) {
		return psa2Header{}, errNotPSA2
	}
	if b[4] != psa2Version {
		return psa2Header{}, errTooNew(b[4])
	}
	if !allZero(b[5:8]) || !allZero(b[28:32]) {
		return psa2Header{}, errUndecryptable
	}
	h := psa2Header{
		chunkSize:     int64(binary.BigEndian.Uint32(b[8:])),
		plaintextSize: int64(binary.BigEndian.Uint64(b[12:])),
		chunkCount:    int64(binary.BigEndian.Uint32(b[20:])),
	}
	copy(h.noncePrefix[:], b[24:28])
	// JS clients cap sizes at 2^53; refuse what they would. A uint64 past
	// int64 reads negative here.
	if h.chunkSize == 0 || h.plaintextSize < 0 || h.plaintextSize > 1<<53-1 ||
		chunkCountFor(h.plaintextSize, h.chunkSize) != h.chunkCount {
		return psa2Header{}, errUndecryptable
	}
	return h, nil
}

func nonceFor(prefix [noncePrefixBytes]byte, index int64) []byte {
	out := make([]byte, 12)
	copy(out, prefix[:])
	binary.BigEndian.PutUint64(out[4:], uint64(index))
	return out
}

func aadFor(header []byte, index int64) []byte {
	return binary.BigEndian.AppendUint32(append([]byte(nil), header...), uint32(index))
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errUndecryptable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealed is an object and what its pointer needs.
type sealed struct {
	object      []byte
	key         []byte
	noncePrefix [noncePrefixBytes]byte
	digest      [32]byte
	chunkSize   int64
}

// sealPadded seals plaintext as a v3 object: padded to its bucket, chunked.
func sealPadded(plaintext []byte) (*sealed, error) {
	if len(plaintext) > MaxAttachmentBytes {
		return nil, fmt.Errorf("attachments are limited to %d MB", MaxAttachmentBytes/1024/1024)
	}
	key := make([]byte, 32)
	var prefix [noncePrefixBytes]byte
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, err
	}
	padded := paddedSizeFor(int64(len(plaintext)))
	return sealChunked(plaintext, padded, key, prefix, chunkSizeFor(padded))
}

// sealChunked is the one chunk loop. The header states sealedSize bytes;
// everything past the end of the file is zeros. The digest is of the file
// alone.
func sealChunked(plaintext []byte, sealedSize int64, key []byte, prefix [noncePrefixBytes]byte, chunkSize int64) (*sealed, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	h := psa2Header{chunkSize: chunkSize, plaintextSize: sealedSize, chunkCount: chunkCountFor(sealedSize, chunkSize), noncePrefix: prefix}
	head := h.bytes()
	object := make([]byte, 0, objectSizeFor(sealedSize, chunkSize))
	object = append(object, head...)
	for i := int64(0); i < h.chunkCount; i++ {
		start := i * chunkSize
		chunk := make([]byte, chunkLen(sealedSize, chunkSize, i))
		if start < int64(len(plaintext)) {
			copy(chunk, plaintext[start:])
		}
		object = aead.Seal(object, nonceFor(prefix, i), chunk, aadFor(head, i))
	}
	return &sealed{object: object, key: key, noncePrefix: prefix, digest: sha256.Sum256(plaintext), chunkSize: chunkSize}, nil
}

// openChunked opens a v2 object (trueSize < 0) or a v3 one (trueSize from
// the pointer). Every byte past the true size must be zero.
func openChunked(object, key, digest []byte, trueSize int64) ([]byte, error) {
	h, err := readHeader(object)
	if err != nil {
		return nil, err
	}
	if int64(len(object)) != objectSizeFor(h.plaintextSize, h.chunkSize) {
		return nil, errIncomplete
	}
	size := h.plaintextSize
	if trueSize >= 0 {
		size = trueSize
	}
	if size > h.plaintextSize {
		return nil, errNotTheOne
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	head := object[:headerBytes]
	out := make([]byte, 0, size)
	at := int64(headerBytes)
	for i := int64(0); i < h.chunkCount; i++ {
		n := chunkLen(h.plaintextSize, h.chunkSize, i) + tagBytes
		chunk, err := aead.Open(nil, nonceFor(h.noncePrefix, i), object[at:at+n], aadFor(head, i))
		if err != nil {
			return nil, errUndecryptable
		}
		at += n
		keep := min(int64(len(chunk)), size-int64(len(out)))
		out = append(out, chunk[:keep]...)
		if !allZero(chunk[keep:]) {
			return nil, errNotTheOne
		}
	}
	if sum := sha256.Sum256(out); !bytes.Equal(sum[:], digest) {
		return nil, errNotTheOne
	}
	return out, nil
}

func openV1(object, key, nonce, digest []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, errUndecryptable
	}
	plaintext, err := aead.Open(nil, nonce, object, nil)
	if err != nil {
		return nil, errUndecryptable
	}
	if sum := sha256.Sum256(plaintext); !bytes.Equal(sum[:], digest) {
		return nil, errNotTheOne
	}
	return plaintext, nil
}

// open opens the object a pointer names.
func (a Attachment) open(object []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(a.Key)
	if err != nil {
		return nil, errUndecryptable
	}
	digest, err := base64.StdEncoding.DecodeString(a.Digest)
	if err != nil {
		return nil, errUndecryptable
	}
	switch a.Version {
	case 0, 1:
		nonce, err := base64.StdEncoding.DecodeString(a.Nonce)
		if err != nil {
			return nil, errUndecryptable
		}
		return openV1(object, key, nonce, digest)
	case 2:
		return openChunked(object, key, digest, -1)
	case 3:
		return openChunked(object, key, digest, a.Size)
	}
	return nil, fmt.Errorf("attachment pointer version %d is newer than this bridge", a.Version)
}

// pointerFor is the pointer to an object sealed by sealPadded and uploaded
// to objectKey.
func pointerFor(s *sealed, objectKey string, size int, m Media) Attachment {
	return Attachment{
		ObjectKey:  objectKey,
		Key:        base64.StdEncoding.EncodeToString(s.key),
		Nonce:      base64.StdEncoding.EncodeToString(s.noncePrefix[:]),
		Digest:     base64.StdEncoding.EncodeToString(s.digest[:]),
		Size:       int64(size),
		Mime:       m.Mime,
		Width:      m.Width,
		Height:     m.Height,
		DurationMS: m.DurationMS,
		Color:      m.Color,
		FileName:   m.FileName,
		Version:    3,
		ChunkSize:  int(s.chunkSize),
	}
}
