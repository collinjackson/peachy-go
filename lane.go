package peachy

// Lane frames: the small JSON payloads that ride a conversation's message
// lane beside the messages themselves. A reaction, a delete and an edit each
// name a message by its frame id (`i`); who sent one is the MLS sender, never
// a payload field.
//
//	{"peachy":"react","v":1,"m":"<id>","e":"👍"}      set
//	{"peachy":"react","v":1,"m":"<id>","x":true}     clear
//	{"peachy":"del","v":1,"m":"<id>"}
//	{"peachy":"edit","v":1,"m":"<id>","n":2,"b":"the whole new text"}
//	{"peachy":"receipt","v":1,"k":"read"|"delivered","m":"<id>"}
//
// Parsing is strict, as on Peachy's clients: RFC 8259 JSON with no
// duplicate key at any depth (two readers that kept different copies would
// disagree), the exact version, and the field types as written. Unknown
// keys are ignored. Tested against Peachy's fixtures (lane_test.go).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	laneReact = "react"
	laneDel   = "del"
	laneEdit  = "edit"
	laneMark  = "receipt"

	// ReceiptRead and ReceiptDelivered are a receipt's kinds. A receipt
	// names the newest message it covers.
	ReceiptRead      = "read"
	ReceiptDelivered = "delivered"

	// MaxEditRevision is the most edits a sender may make to one message.
	MaxEditRevision = 10
	maxEmojiBytes   = 32
)

// lane is one parsed lane frame. Kind is "" for anything that isn't a
// reaction, delete or edit this bridge reads.
type lane struct {
	kind     string
	target   string
	emoji    string
	remove   bool
	revision int
	text     string
	receipt  string
	// A lane mark: the receipt a device owes for a reaction, edit or delete
	// it opened. It names that frame's envelope, never a message, so it is
	// never shown as a receipt.
	laneMark bool
}

func parseLane(plaintext []byte) lane {
	fields, ok := strictObject(plaintext)
	if !ok {
		return lane{}
	}
	var kind string
	if json.Unmarshal(fields["peachy"], &kind) != nil || string(fields["v"]) != "1" {
		return lane{}
	}
	var target string
	if json.Unmarshal(fields["m"], &target) != nil || target == "" {
		return lane{}
	}
	l := lane{kind: kind, target: target}
	switch kind {
	case laneReact:
		if string(fields["x"]) == "true" {
			l.remove = true
			return l
		}
		if json.Unmarshal(fields["e"], &l.emoji) != nil || !ValidEmoji(l.emoji) {
			return lane{}
		}
		return l
	case laneDel:
		return l
	case laneMark:
		if json.Unmarshal(fields["k"], &l.receipt) != nil {
			return lane{}
		}
		switch {
		case l.receipt == "lane":
			l.receipt, l.laneMark = ReceiptDelivered, true
		case l.receipt != ReceiptRead && l.receipt != ReceiptDelivered:
			return lane{}
		case l.receipt == ReceiptDelivered && string(fields["l"]) == "true":
			// The shape builds of 2026-10-29 sent a lane mark in.
			l.laneMark = true
		}
		return l
	case laneEdit:
		n, err := strconv.Atoi(string(fields["n"]))
		if err != nil || n < 1 || n > MaxEditRevision {
			return lane{}
		}
		if json.Unmarshal(fields["b"], &l.text) != nil || strings.TrimSpace(l.text) == "" {
			return lane{}
		}
		l.revision = n
		return l
	}
	return lane{}
}

func encodeReaction(target, emoji string, remove bool) ([]byte, error) {
	if remove {
		return json.Marshal(map[string]any{"peachy": laneReact, "v": 1, "m": target, "x": true})
	}
	if !ValidEmoji(emoji) {
		return nil, errors.New("Peachy reactions are a single emoji")
	}
	return json.Marshal(map[string]any{"peachy": laneReact, "v": 1, "m": target, "e": emoji})
}

func encodeDelete(target string) ([]byte, error) {
	return json.Marshal(map[string]any{"peachy": laneDel, "v": 1, "m": target})
}

func encodeReceipt(kind, target string) ([]byte, error) {
	return json.Marshal(map[string]any{"peachy": laneMark, "v": 1, "k": kind, "m": target})
}

func encodeEdit(target string, revision int, text string) ([]byte, error) {
	if revision < 1 || revision > MaxEditRevision {
		return nil, errors.New("Peachy allows ten edits per message")
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("an edit can't be empty; delete the message instead")
	}
	return json.Marshal(map[string]any{"peachy": laneEdit, "v": 1, "m": target, "n": revision, "b": text})
}

// strictObject reads b as one JSON object with no duplicate key anywhere in
// it, keys compared after unescaping.
func strictObject(b []byte) (map[string]json.RawMessage, bool) {
	if !json.Valid(b) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if !noDuplicates(dec) {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

// noDuplicates walks one JSON value from dec, refusing an object that names
// a key twice.
func noDuplicates(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return false
			}
			k, _ := key.(string)
			if seen[k] {
				return false
			}
			seen[k] = true
			if !noDuplicates(dec) {
				return false
			}
		}
		_, err = dec.Token()
		return err == nil
	case json.Delim('['):
		for dec.More() {
			if !noDuplicates(dec) {
				return false
			}
		}
		_, err = dec.Token()
		return err == nil
	}
	return true
}

// ValidEmoji is Peachy's reaction rule: one emoji (a single grapheme of
// emoji code points with at least one picture), at most 32 UTF-8 bytes.
func ValidEmoji(s string) bool {
	if s == "" || len(s) > maxEmojiBytes || !utf8.ValidString(s) {
		return false
	}
	rs := []rune(s)
	i := 0
	for {
		n := emojiElement(rs[i:])
		if n == 0 {
			return false
		}
		i += n
		if i == len(rs) {
			return true
		}
		if rs[i] != zwj || i+1 == len(rs) {
			return false
		}
		i++
	}
}

const (
	zwj        = 0x200D
	vs15       = 0xFE0E
	vs16       = 0xFE0F
	keycap     = 0x20E3
	tagCancel  = 0xE007F
	riFirst    = 0x1F1E6
	riLast     = 0x1F1FF
	toneFirst  = 0x1F3FB
	toneLast   = 0x1F3FF
	tagFirst   = 0xE0020
	tagLastRun = 0xE007E
)

// emojiElement is how many runes at the start of rs make one emoji between
// joiners: a flag (two regional indicators), a keycap, or a picture with its
// presentation selector, skin tone and tag sequence. 0 when none starts there.
func emojiElement(rs []rune) int {
	if len(rs) == 0 {
		return 0
	}
	r := rs[0]
	switch {
	case r >= riFirst && r <= riLast:
		if len(rs) >= 2 && rs[1] >= riFirst && rs[1] <= riLast {
			return 2
		}
		return 0
	case r == '#' || r == '*' || (r >= '0' && r <= '9'):
		i := 1
		if i < len(rs) && rs[i] == vs16 {
			i++
		}
		if i < len(rs) && rs[i] == keycap {
			return i + 1
		}
		return 0
	case !pictographic(r):
		return 0
	}
	i := 1
	if i < len(rs) && (rs[i] == vs16 || rs[i] == vs15) {
		i++
	}
	if i < len(rs) && rs[i] >= toneFirst && rs[i] <= toneLast {
		i++
	}
	if i < len(rs) && rs[i] >= tagFirst && rs[i] <= tagLastRun {
		for i < len(rs) && rs[i] >= tagFirst && rs[i] <= tagLastRun {
			i++
		}
		if i == len(rs) || rs[i] != tagCancel {
			return 0
		}
		i++
	}
	return i
}

// pictographic approximates Unicode's Extended_Pictographic: the emoji
// blocks plus the older symbols that have an emoji presentation.
func pictographic(r rune) bool {
	switch {
	case r >= toneFirst && r <= toneLast:
		return false // a skin tone alone is no picture
	case r >= 0x1F000 && r <= 0x1FAFF, r >= 0x1FC00 && r <= 0x1FFFD:
		return true
	case r >= 0x2600 && r <= 0x27BF, r >= 0x2300 && r <= 0x23FF, r >= 0x2B00 && r <= 0x2BFF:
		return true
	case r >= 0x2190 && r <= 0x21FF, r >= 0x25A0 && r <= 0x25FF, r >= 0x2900 && r <= 0x297F:
		return true
	}
	switch r {
	case 0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x24C2, 0x3030, 0x303D, 0x3297, 0x3299:
		return true
	}
	return false
}
