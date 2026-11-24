package peachy

// What this device reads of bots (peachy-protocol's docs/bots.md): a leaf
// whose credential is a pdc3 is a bot's (member_kind), and what a person's
// device addresses to one. Bot state keys (bot, bots, bat, pol.bot, ...) are
// the core's to judge; this package only carries them, as it carries every
// key of the group's state it doesn't change.

import (
	"encoding/json"
)

// holdsBotLocked is whether group's tree holds a bot leaf. Called with d.mu
// held.
func (d *Device) holdsBotLocked(group []byte) bool {
	if d.mls == nil {
		return false
	}
	roster, err := d.mls.roster(group)
	if err != nil {
		return false
	}
	for _, m := range roster {
		if m.bot {
			return true
		}
	}
	return false
}

// personToBot is whether group is a person-to-bot chat: its state says
// "bot": "dm" in a direct chat, and its tree holds exactly one person and
// at most one bot leaf (docs/bots.md, Conventions). Called with d.mu held.
func (d *Device) personToBot(group []byte, roster []member) bool {
	raw, err := d.mls.meta(group)
	if err != nil || raw == nil {
		return false
	}
	var meta struct {
		DM  bool   `json:"dm"`
		Bot string `json:"bot"`
	}
	if json.Unmarshal(raw, &meta) != nil || !meta.DM || meta.Bot != "dm" {
		return false
	}
	people, bots := map[string]bool{}, 0
	for _, m := range roster {
		if m.bot {
			bots++
		} else {
			people[m.actorID] = true
		}
	}
	return len(people) == 1 && bots <= 1
}
