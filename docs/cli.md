---
title: Peachy in a terminal
---

# Peachy in a terminal

[← peachy-go](../README.md)

`peachy` is a small command-line tool built from the same code as the bridge.
It reads and sends Peachy messages from a terminal, without Matrix or Beeper.
It's a separate device on your account, with its own entry in Peachy's
**Devices** list ("Peachy CLI").

`./build.sh` builds it (see the [README](../README.md#build)).

## Connect it

```
peachy login +15551234567
```

Type the code from the text message. Then open Peachy on your phone, tap
**add another device**, and pick the number the terminal shows. The phone then
shows a number of its own: type it into the terminal, which offers it among
two others. That second pick is what tells the terminal the account key came
from your phone and not from anyone in between, so if the phone's number
isn't offered, answer 0 and start over on both devices.

## Use it

```
peachy chats                      # your conversations
peachy read Sam                   # messages that arrived since you connected
peachy send Sam "on my way"       # send words
echo "on my way" | peachy send Sam
peachy send Sam -f photo.jpg "the view"
peachy follow                     # print messages as they arrive; Ctrl-C stops
peachy follow "Mission Cycling"   # just one chat
```

A chat can be named by its name, by someone in it, or by the start of its id
(the first column of `peachy chats`).

## Replies, reactions, edits and deletes

`read` shows each message's id in brackets. Name a message by the first few
characters of that id (at least 4), or by `last` for the newest one:

```
Oct 28 14:26  [187dd9de] Sam: ride at 9?
Oct 28 14:27  [26e2ba6c] you: yes, 9 works  (edited)  ↪ 187dd9de
                   👍 you
```

```
peachy send Sam -r 187d "yes, 9 works"   # reply to a message
peachy react Sam 187d 👍                 # one emoji; a new one replaces it
peachy unreact Sam 187d                  # take your reaction back
peachy edit Sam last "yes, 9 works for me"
peachy delete Sam last                   # deletes it for everyone
```

Peachy's rules apply: you can edit or delete only your own messages, and
edits are allowed for 24 hours, up to ten per message.

## Good to know

- **Old messages don't come along.** Like the bridge, a new device sees only
  messages sent after it connects. `read` shows what it has received since.
- **It uses your Peachy settings.** It shows the names you gave people, and
  nothing from people you blocked.
- **It keeps what it receives**, and what you send from it, in its data
  folder, so `read` can show it.
- **Disappearing messages disappear here too.** Yours count down from when
  you sent them; anyone else's from when `read` or `follow` first showed them,
  or you read them on another device. Once the time is up they're deleted
  from the data folder.
- **One command at a time.** While `peachy follow` runs, other `peachy`
  commands wait for it to stop. Stop it with Ctrl-C first.
- **The data folder holds your keys.** It's `~/Library/Application
  Support/peachy-cli` on a Mac and `~/.config/peachy-cli` on Linux (`-d` or
  `PEACHY_DIR` changes it). Anyone who can read it can read your messages.
- **Disconnecting:** remove "Peachy CLI" from Peachy's **Devices** list, then
  delete the data folder.
