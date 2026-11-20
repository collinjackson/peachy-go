package peachy

// Mentions, as Peachy's apps write them: the sender's device finds each
// @handle in the words and puts who it names into the message, so a reader
// whose chat is muted except for mentions still hears about it. The rules are
// Peachy's mention fixture's (mls/fixtures/formats/mention.json in peachy-protocol).

import "strings"

// Mention is a person a message names.
type Mention struct {
	UserID string
	Handle string // lowercase, without the @
}

// MaxMentions is how many people one message may name; past it, handles
// stay text.
const MaxMentions = 10

// FindMentions reads the @handles in text, as Peachy's server matches them:
// a handle is 3 to 30 of [a-z0-9_], any case, not after a letter, digit, _,
// @ or /, and not followed by one. Lowercased, each once, in order.
// @all is among them.
func FindMentions(text string) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; i < len(text); i++ {
		if text[i] != '@' || i > 0 && (handleByte(text[i-1]) || text[i-1] == '@' || text[i-1] == '/') {
			continue
		}
		j := i + 1
		for j < len(text) && handleByte(text[j]) {
			j++
		}
		if n := j - i - 1; n >= 3 && n <= 30 {
			h := strings.ToLower(text[i+1 : j])
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
		i = j - 1
	}
	return out
}

func handleByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// ResolveMentions is what a message with these words carries: the members
// it names, and whether it names everyone (@all, in a group only; in a DM
// it's just words). Handles of people not in the chat stay text.
func ResolveMentions(text string, members []Person, group bool) (people []Mention, everyone bool) {
	byHandle := map[string]string{}
	for _, p := range members {
		if p.Handle != "" {
			byHandle[strings.ToLower(p.Handle)] = p.ID
		}
	}
	for _, h := range FindMentions(text) {
		if h == "all" {
			everyone = everyone || group
			continue
		}
		if id, ok := byHandle[h]; ok && len(people) < MaxMentions {
			people = append(people, Mention{UserID: id, Handle: h})
		}
	}
	return people, everyone
}

// decodeMentions reads a frame's m, dropping any entry with no user id, as
// Peachy's apps do.
func decodeMentions(raw []struct {
	U string `json:"u"`
	H string `json:"h"`
}) []Mention {
	var out []Mention
	for _, m := range raw {
		if m.U != "" {
			out = append(out, Mention{UserID: m.U, Handle: m.H})
		}
	}
	return out
}
