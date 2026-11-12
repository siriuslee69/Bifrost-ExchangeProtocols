# UI plan of the desktop demo (`src/clients/desktop/`)

The demo is one window that sends a short text to another machine on the same
network and shows what came back. It exists to show Bifrost's message frames
(BMSG over TCP) at work. It is not a messenger product.

```text
╭⟢ 1. What the demo is for (way 1: intention) 🌊
├⟢ 2. What similar programs have (way 2) 🍣
├⟢ 3. The press budget 🐦‍🔥
├⟢ 4. The walks (way 3) 🌿
├⟢ 5. The values the user may change (way 4) ❧
├⟢ 6. What people say about such programs (way 5) ✜
├⟢ 7. The six states of the message list ◈
╰⟢ 8. The colours ⟡
```

## 1. What the demo is for

```text
  goal 1   A user can send a short text to a machine on the same network by
           typing its address and pressing Enter.
  goal 2   A user can see, on the same page, whether it arrived: an
           acknowledgement row, or an error row that says why not.
  goal 3   A user can see what another machine sent to this one.
  not      No accounts, no history kept on disk, no groups, no files. The
           frames are the subject, not the chat.
```

## 2. What similar programs have

Taken from memory, not looked up (no web search was made for this plan).

```text
  program kind              has                                     this demo
  ------------------------  --------------------------------------  ---------------
  LAN message tools         peer list, discovery, send, history     keep: send
                                                                    prune: the rest
                                                                    (no goal needs it)
  messengers                chats, groups, read marks, settings     prune: not a goal
```

## 3. The press budget

A press rate is presses per day for one person (UI.md 2.2). They were counted
by walking three ordinary days (section 4), not guessed from the layout.

```text
  button or action                    presses/day   tier   where it lives
  ----------------------------------  -----------   ----   -------------------------
  send a message (Enter or SEND)               12   A      composer, right end, loud
  type a message (focus the field)             12   A      composer, takes the width
  type the peer address                         1   A      left panel, always shown
  clear the message list (X)                  0.3   B      composer, left end, quiet
```

Everything of tier A is on the page and reachable by Tab. The one loud thing is
SEND (the `recommendation` colour). The clear button destroys only what is on
the screen, so it needs no confirmation: it is not stored anywhere.

## 4. The walks

```text
  walk: "send a line to the machine next to me"          needs
  ------------------------------------------------      ------------------------------
  1. open the demo                                       the status shows LISTENING
  2. type the peer address                               a field; placeholder "peer ip"
  3. type the message, press Enter                       2 presses (type, Enter)
  4. the peer answers                                    an ack row, gold line
  5. (peer address empty)                                an error row: "peer IP is empty"
  6. (peer not reachable)                                an error row with the reason
  7. (message empty)                                     nothing is sent; the field keeps focus
  8. (wrong peer address typed)                          the peer field keeps its text, so it
                                                         is corrected in place; the message
                                                         field is empty after a send
```

Daily walk length: 2 presses. That is within the limit of 3 (UI.md 2.3).

```text
  the first day    open, type the address, type a line, send
  a bad day        steps 5 to 7 above
  a change in life none: nothing is kept between runs
  the other side   the peer's own demo shows the line and answers with an ack
```

## 5. The values the user may change

```text
  value               who would want it otherwise?       decision
  ------------------  ---------------------------------  ----------------------------
  port 48371          nobody for a demo                  fixed (const in app.nim)
  polling gap 350 ms  nobody                             fixed
  list limit 240      nobody                             fixed (oldest rows leave)
  theme               follows the system                 no control: nothing to set
```

There is no settings page. A control that sets nothing the demo reads is not
drawn (UI.md 8, "Settings").

## 6. What people say about such programs

Taken from memory, not looked up.

```text
  complaint                         becomes a rule here
  --------------------------------  ----------------------------------------------
  "did it arrive?"                  every send answers on the page: ack or error
  "nothing happens when I press"    an error row says why (empty address, no route)
```

## 7. The six states of the message list

```text
  empty      "Channel ready" with one line saying where messages stay
  loading    the SEND button is disabled while a send is running
  one        a single row; it does not stretch (rows have a fixed look)
  many       rows stack; the list scrolls and follows the newest
  too many   after 240 rows the oldest leave (`maxRows` in app.js): a peer on
             the network cannot make the page grow for ever
  failed     a red row with the reason; never a blank page
```

## 8. The colours

All colours are defined once, in `src/clients/desktop/web/tokens.css`, for a dark
theme (the default) and a light theme (when the system asks for it). `app.css`
only names them. `evaluation/tests/test_ui_contrast.nim` checks that every
pair of text on its background reaches a contrast of 4.5 to 1 in both themes.

```text
  checked by the test        not looked at (no screen was available to the agent)
  ------------------------   -----------------------------------------------------
  text on panel, both themes the window in the running app (nimble runWebui)
  fill on text, both themes  the hover and focus look of the buttons by eye
```
