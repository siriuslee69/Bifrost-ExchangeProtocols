## -----------------------------------------------------------------------
## UI Contrast <- text on its background reaches 4.5 to 1, in both themes
## -----------------------------------------------------------------------
##
## Reads `src/clients/desktop/web/tokens.css` and checks what UI.md 6 asks:
##
##   1. text is readable on what it stands on, in the dark AND the light theme
##   2. the light theme defines every role the dark theme defines
##   3. app.css types no colour (it only names the tokens)
##
## A "contrast of 4.5 to 1" is the number the web accessibility rules (WCAG)
## give for body text: the lighter colour is at least 4.5 times as bright as
## the darker one, once both are measured the way the eye sees them.
##
##   see-through panel over a gradient  ->  the colour changes from corner to
##   corner, so every pair is measured over ALL THREE stops of the gradient
##   and the WORST one must still pass:
##
##        bg-1 ──────── bg-2 ──────── bg-3        (panel + glue laid on top)
##         ^              ^              ^
##       measured       measured       measured

import std/[unittest, os, strutils, tables, math]

import runePragmas

type
  Rgba = tuple[r, g, b, a: float]
    ## one colour: red, green, blue as 0..255 and alpha as 0..1.
  Tokens = Table[string, Rgba]
    ## token name without the leading `--`, and its colour.
  Pair = tuple[fg: string, layers: seq[string]]
    ## fg: the token of the text. layers: what lies under it, bottom first.

const
  minRatio: float = 4.5
  gradientStops: array[3, string] = ["bg-1", "bg-2", "bg-3"]

proc webFile(name: string): string {.role: helper.} =
  ## name: a file of the desktop demo's web folder.
  result = currentSourcePath().parentDir() / ".." / ".." / "src" / "clients" /
    "desktop" / "web" / name

proc pairList(): seq[Pair] {.role: configurator.} =
  ## Every text-on-background pair the page uses.
  result = @[
    (fg: "text", layers: @["panel"]),
    (fg: "muted", layers: @["panel"]),
    (fg: "faint", layers: @["panel"]),
    (fg: "tiny", layers: @["panel"]),
    (fg: "tiny-b", layers: @["panel"]),
    (fg: "recommendation", layers: @["panel"]),
    (fg: "good", layers: @["panel"]),
    (fg: "warn", layers: @["panel"]),
    (fg: "bad", layers: @["panel"]),
    (fg: "text", layers: @["panel", "glue-bar"]),
    (fg: "text", layers: @["panel", "glue-in"]),
    (fg: "text", layers: @["panel", "glue-out"]),
    (fg: "muted", layers: @["panel", "glue-ack"]),
    (fg: "bad", layers: @["panel", "glue-bad"]),
    (fg: "tiny", layers: @["panel", "glue-status"]),
    (fg: "on-fill", layers: @["recommendation"]),
    (fg: "on-fill", layers: @["active"])
  ]

proc parseColour(s: string): tuple[ok: bool, c: Rgba] {.role: parser.} =
  ## s: a CSS colour written as #rrggbb or rgba(r, g, b, a). Anything else is
  ## not ok.
  var
    t: string = s.strip()
    parts: seq[string] = @[]
  result = (ok: false, c: (r: 0.0, g: 0.0, b: 0.0, a: 1.0))
  if t.len == 7 and t[0] == '#':
    result = (ok: true, c: (r: float(parseHexInt(t[1 .. 2])),
      g: float(parseHexInt(t[3 .. 4])), b: float(parseHexInt(t[5 .. 6])),
      a: 1.0))
    return
  if not (t.startsWith("rgba(") and t.endsWith(")")):
    return
  parts = t[5 .. ^2].split(',')
  if parts.len != 4:
    return
  result = (ok: true, c: (r: parseFloat(parts[0].strip()),
    g: parseFloat(parts[1].strip()), b: parseFloat(parts[2].strip()),
    a: parseFloat(parts[3].strip())))

proc readTokens(css: string): Tokens {.role: parser.} =
  ## css: a stretch of tokens.css. Every `--name: colour;` line is collected.
  var
    L: seq[string] = css.splitLines()
    t: string = ""
    colon: int = 0
    semi: int = 0
    got: tuple[ok: bool, c: Rgba] = (ok: false, c: (r: 0.0, g: 0.0, b: 0.0,
      a: 1.0))
  for raw in L:
    t = raw.strip()
    if not t.startsWith("--"):
      continue
    colon = t.find(':')
    semi = t.find(';')
    if colon < 0 or semi < colon:
      continue
    got = parseColour(t[colon + 1 ..< semi])
    if got.ok:
      result[t[2 ..< colon]] = got.c

proc themeTokens(light: bool): Tokens {.role: dataFetcher.} =
  ## light: false reads the dark theme (everything before the @media block),
  ## true the light theme (the @media block).
  var
    css: string = readFile(webFile("tokens.css"))
    media: int = css.find("@media")
  if light:
    result = readTokens(css[media .. ^1])
  else:
    result = readTokens(css[0 ..< media])

proc over(top, under: Rgba): Rgba {.role: math.} =
  ## top painted over under (under counts as solid): the usual alpha blend.
  result.r = top.r * top.a + under.r * (1.0 - top.a)
  result.g = top.g * top.a + under.g * (1.0 - top.a)
  result.b = top.b * top.a + under.b * (1.0 - top.a)
  result.a = 1.0

proc channel(v: float): float {.role: math.} =
  ## v: one colour channel, 0..255. The eye's response, 0..1.
  var
    c: float = v / 255.0
  if c <= 0.03928:
    result = c / 12.92
  else:
    result = pow((c + 0.055) / 1.055, 2.4)

proc luminance(c: Rgba): float {.role: math.} =
  ## c: a solid colour. How bright it looks, 0 (black) .. 1 (white).
  result = 0.2126 * channel(c.r) + 0.7152 * channel(c.g) +
    0.0722 * channel(c.b)

proc contrast(a, b: Rgba): float {.role: math.} =
  ## a/b: two solid colours. 1 means equal, 21 means black on white.
  var
    la: float = luminance(a)
    lb: float = luminance(b)
  result = (max(la, lb) + 0.05) / (min(la, lb) + 0.05)

proc stack(T: Tokens, stop: string, layers: seq[string]): Rgba {.role: math.} =
  ## T/stop/layers: the colour seen where `layers` (bottom first) lie over the
  ## gradient stop `stop`.
  var
    i: int = 0
  result = T[stop]
  while i < layers.len:
    result = over(T[layers[i]], result)
    i = i + 1

proc worstContrast(T: Tokens, p: Pair): float {.role: math.} =
  ## T/p: the theme and one text-on-background pair. The lowest contrast over
  ## the three gradient stops.
  var
    i: int = 0
    under: Rgba = (r: 0.0, g: 0.0, b: 0.0, a: 1.0)
    ink: Rgba = (r: 0.0, g: 0.0, b: 0.0, a: 1.0)
  result = 1000.0
  while i < gradientStops.len:
    under = stack(T, gradientStops[i], p.layers)
    ink = over(T[p.fg], under)
    result = min(result, contrast(ink, under))
    i = i + 1

proc failingPairs(T: Tokens): seq[string] {.role: parser.} =
  ## T: one theme. One line for every pair that stays under the minimum, such
  ## as "faint on panel is 1.83 to 1". Empty when every pair passes.
  var
    P: seq[Pair] = pairList()
    r: float = 0.0
  for p in P:
    r = worstContrast(T, p)
    if r < minRatio:
      result.add(p.fg & " on " & p.layers.join("+") & " is " &
        r.formatFloat(ffDecimal, 2) & " to 1")

proc missingRoles(A, B: Tokens): seq[string] {.role: helper.} =
  ## A/B: two themes. The names A defines and B does not.
  for k in A.keys:
    if not B.hasKey(k):
      result.add(k)

proc typedColours(css: string): int {.role: parser.} =
  ## css: a style sheet. How many colours are written out in it.
  var
    i: int = 0
  while i < css.len:
    if css[i] == '#' and i + 7 <= css.len and
        css[i + 1 .. i + 6].allCharsInSet(HexDigits):
      result = result + 1
    if css.continuesWith("rgba(", i) or css.continuesWith("rgb(", i):
      result = result + 1
    i = i + 1

suite "desktop demo colours":

  # {.testKind: tkProperty, covers: "tokens.css".}
  test "dark theme: every text reaches 4.5 to 1 on what it stands on":
    var
      bad: seq[string] = failingPairs(themeTokens(false))
    checkpoint(bad.join("; "))
    check bad.len == 0

  # {.testKind: tkProperty, covers: "tokens.css".}
  test "light theme: every text reaches 4.5 to 1 on what it stands on":
    var
      bad: seq[string] = failingPairs(themeTokens(true))
    checkpoint(bad.join("; "))
    check bad.len == 0

  # {.testKind: tkRegression, covers: "tokens.css".}
  test "each theme defines every role the other defines":
    check missingRoles(themeTokens(false), themeTokens(true)).len == 0
    check missingRoles(themeTokens(true), themeTokens(false)).len == 0

  # {.testKind: tkRegression, covers: "app.css".}
  test "app.css types no colour: it only names the tokens":
    check typedColours(readFile(webFile("app.css"))) == 0
