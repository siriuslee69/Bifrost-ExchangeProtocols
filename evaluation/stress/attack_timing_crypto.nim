## ------------------------------------------------------------------------
## attack_timing_crypto <- does the time a primitive takes give a secret away?
## ------------------------------------------------------------------------
##
## A remote attacker cannot see a key. He can see how long an answer took. If the
## time depends on a secret (or on whether a forged input was "almost right") he
## can learn it, one guess at a time. Two questions per primitive:
##
##   validity   A = decapsulate a valid ciphertext, B = one with a flipped byte
##              If B differs, the attacker learns whether his forged ciphertext
##              was valid: that is the oracle behind chosen-ciphertext attacks
##              (KyberSlash, re-encryption compare timing, Marvin, ...).
##   position   A = corrupt the FIRST byte, B = corrupt the LAST byte
##              If they differ, something stops early at the first difference.
##
## Each probe runs twice with different seeds; LEAK counts only when both runs
## say LEAK with the same sign. Run pinned to one core on a quiet machine:
##
##   taskset -c 3 nim c -r -d:release evaluation/stress/attack_timing_crypto.nim

import std/[strutils, os]
import nidhogg_attacklab
import ../../src/protocols/byte_codec
import tyr/kems/saber/operations as saber
import tyr/kems/saber/params as saberParams
import tyr/kems/mlkem/operations as mlkem
import tyr/kems/mlkem/params as mlkemParams
import tyr/kems/ntru/operations as ntru
import tyr/kems/ntru/params as ntruParams
import tyr/kems/frodo/operations as frodo
import tyr/kems/frodo/params as frodoParams
import runePragmas

type
  DecapsFn = proc (sk, ct: seq[byte]): seq[byte] {.closure.}

var
  sink: seq[byte] = @[]
  worstLeaks: int = 0

proc twice(fa, fb: proc () {.closure.}, rounds, reps: int): tuple[v: LeakVerdict,
    confirmed: bool] {.role: orchestrator.} =
  ## Two runs, different seeds. confirmed: both LEAK, same sign.
  var
    a: LeakVerdict = measureLeak(fa, fb, rounds = rounds, reps = reps, seed = 1'u64)
    b: LeakVerdict = measureLeak(fa, fb, rounds = rounds, reps = reps, seed = 2'u64)
  result.v = a
  result.confirmed = a.kind == lkLeak and b.kind == lkLeak and
    (a.t < 0.0) == (b.t < 0.0)

proc show(label: string, r: tuple[v: LeakVerdict, confirmed: bool]) {.role: dataWriter.} =
  var
    tag: string = if r.confirmed: "LEAK*" else: "ok   "
  echo "  ", label.alignLeft(34), " ", tag, " ", r.v.render()
  if r.confirmed:
    worstLeaks = worstLeaks + 1

proc probeKem(name: string, sk, ct: seq[byte], f: DecapsFn, rounds: int) {.
    role: orchestrator.} =
  var
    last: seq[byte] = ct
    first: seq[byte] = ct
  last[last.high] = last[last.high] xor 1'u8
  first[0] = first[0] xor 1'u8
  echo name, "  (ciphertext ", ct.len, " B)"
  show("valid vs last byte flipped", twice(
    proc () = sink = f(sk, ct), proc () = sink = f(sk, last), rounds, 1))
  show("first byte vs last byte flipped", twice(
    proc () = sink = f(sk, first), proc () = sink = f(sk, last), rounds, 1))

proc probeSaber(v: SaberVariant, rounds: int) {.role: orchestrator.} =
  var
    kp = saber.saberTyrKeypair(v)
    c = saber.saberTyrEncaps(v, kp.publicKey)
  probeKem("SABER " & $v, kp.secretKey, c.ciphertext,
    proc (sk, ct: seq[byte]): seq[byte] = saber.saberTyrDecaps(v, sk, ct), rounds)

proc probeMlKem(v: MlKemVariant, rounds: int) {.role: orchestrator.} =
  var
    kp = mlkem.mlkemTyrKeypair(v)
    c = mlkem.mlkemTyrEncaps(v, kp.publicKey)
  probeKem("ML-KEM " & $v, kp.secretKey, c.ciphertext,
    proc (sk, ct: seq[byte]): seq[byte] = mlkem.mlkemTyrDecaps(v, sk, ct), rounds)

proc probeNtru(v: NtruVariant, rounds: int) {.role: orchestrator.} =
  var
    kp = ntru.ntruTyrKeypair(v)
    c = ntru.ntruTyrEncaps(v, kp.publicKey)
  probeKem("NTRU " & $v, kp.secretKey, c.ciphertext,
    proc (sk, ct: seq[byte]): seq[byte] = ntru.ntruTyrDecaps(v, sk, ct), rounds)

proc probeFrodo(v: FrodoVariant, rounds: int) {.role: orchestrator.} =
  var
    kp = frodo.frodoTyrKeypair(v)
    c = frodo.frodoTyrEncaps(v, kp.publicKey)
  probeKem("Frodo " & $v, kp.secretKey, c.ciphertext,
    proc (sk, ct: seq[byte]): seq[byte] = frodo.frodoTyrDecaps(v, sk, ct), rounds)

proc probeCompare() {.role: orchestrator.} =
  ## Bifrost's tag comparison: a tag wrong in the first byte against one wrong
  ## in the last byte. Plain `==` on two seqs would stop at the first byte.
  var
    good: seq[byte] = newSeq[byte](32)
    first: seq[byte] = newSeq[byte](32)
    last: seq[byte] = newSeq[byte](32)
    ok: bool = false
  first[0] = 1
  last[31] = 1
  echo "constantTimeEqual  (32-byte tags)"
  show("wrong at first byte vs at last", twice(
    proc () = ok = constantTimeEqual(good, first),
    proc () = ok = constantTimeEqual(good, last), 20_000, 256))
  echo "plain == on seqs   (the thing it replaces; expected to leak)"
  show("wrong at first byte vs at last", twice(
    proc () = ok = (good == first), proc () = ok = (good == last), 20_000, 256))
  if ok: echo ""

proc main() {.role: orchestrator.} =
  var
    quick: bool = paramCount() > 0 and paramStr(1) == "--quick"
    n: int = if quick: 600 else: 3000
  probeCompare()
  probeSaber(fireSaber, n)
  probeSaber(lightSaber, n)
  probeMlKem(mlkem768, n)
  probeMlKem(mlkem1024, n)
  probeNtru(ntruHps2048677, n)
  probeFrodo(frodo640shake, n div 6)
  echo ""
  echo "confirmed leaks (LEAK*): ", worstLeaks, "   (the plain == probe is expected to count one)"

main()
