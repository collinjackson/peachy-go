---
title: Bots on Peachy
---

# Bots on Peachy

[← peachy-go](../README.md)

`peachy daemon` lets chat bots run on Peachy. It answers the same HTTP API as
[signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api), so a
bot written for Signal that way runs on Peachy by pointing its bridge URL at
the daemon. A new bot can use the same API from any language.

## Set it up

1. Make a Peachy account for the bot, with its own phone number.
2. Link the daemon's device to it, with its own data folder:

   ```
   peachy -d ~/peachy-bot login -name "My bot" +15551234567
   ```

3. Start the daemon:

   ```
   peachy -d ~/peachy-bot daemon
   ```

   It answers on `http://127.0.0.1:8080` (`-listen` changes it). To answer
   beyond this machine it needs `-token`, which bots then send as
   `Authorization: Bearer <token>`.

   Add `-mode json-rpc` for a bot that receives over a WebSocket, as with
   signal-cli-rest-api's json-rpc mode. Com Tower does: it then hears each
   message the moment Peachy delivers it, rather than at its next poll.

4. Point the bot at it, for example `SIGNAL_CLI_URL=http://127.0.0.1:8080`.

People add the bot's account to a group, or message it, and it sees what
they write there. A DM from someone new would be a message request on the
bot's account; the daemon accepts it, since a bot answers whoever writes.

## What it answers

| Call | Does |
|---|---|
| `GET /v1/receive/{number}` | what arrived since the last call: messages and reactions. Opened as a WebSocket, each one as it arrives, as `{"jsonrpc":"2.0","method":"receive","params":{"envelope":…,"account":…}}`. In `-mode json-rpc`, only the WebSocket. |
| `POST /v2/send` | words, photos (`base64_attachments`), replies (`quote_timestamp`), mentions |
| `POST /v1/reactions/{number}` | react to a message; `DELETE` takes it back |
| `GET /v1/groups/{number}` | the bot's group chats |
| `GET /v1/about` | that it's up |

`{number}` is whatever the bot calls itself.

## How Peachy differs from Signal

- **People are ids, not phone numbers.** Peachy never shows anyone's number,
  so `sourceNumber` is empty and a person is their `sourceUuid`. To DM
  someone, send to that id (a `+` in front is fine). The bot can DM someone
  only once they've messaged it: starting a new chat isn't in Peachy's
  published protocol yet.
- **Groups:** `groupInfo.groupId` is the chat's Peachy id; send to
  `group.` + base64 of it, as with signal-cli.
- **Messages are named by timestamp,** as in Signal. The daemon gives each
  one a timestamp unique to the bot, so replies and reactions find it.
- **Mentions** are real Peachy mentions, so someone who muted the chat
  except for mentions still hears about it. In what the bot sends, each
  mention becomes `@handle` in the words. In what it receives, the words keep
  the `@handle` (where signal-cli would put a placeholder), and `mentions`
  says where it is (`start` and `length` in UTF-16 units, `uuid` the
  person). `@all` in a group names everyone. Someone with no Peachy handle
  can't be mentioned; the words get their name instead.
- **Reactions** are one emoji, as in the Peachy apps.
- **Disappearing messages:** `expiresInSeconds` is a message's timer, as in
  Signal. A bot that keeps messages should drop them once it's up. What the
  bot sends carries the chat's timer.
- **Not passed on:** messages from people the bot's account blocked, edits,
  deletes, and receipts.

## Good to know

- **Collect often,** or keep a WebSocket open. The daemon holds up to 2,000 messages for a bot that
  isn't collecting, then drops the oldest.
- **One process per device.** The daemon holds the device's data folder;
  other `peachy` commands on it wait until the daemon stops.
- **The data folder holds the bot's keys.** Keep it private.
- **A chat the bot fell behind in recovers by itself.** When three messages in a row from one
  group fail to open ("epoch differs"), the daemon forgets its copy of the group and sends the
  members' devices a signed seat ask, as Peachy's apps do. The next member device that drains it
  seats the bot again, and the chat works from then on. Until then sends to that group fail, and
  the ask repeats, from 10 minutes up to every 6 hours. `peachy rejoin CHAT` does the same by hand.
  Messages sent while the bot was out stay unreadable to it.
