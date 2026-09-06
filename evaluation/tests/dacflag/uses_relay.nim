## Uses the assembled relay. Must NOT build under -d:bifrostDac=off.
## Imported directly rather than through the umbrella, because the umbrella's
## `when` block would hide a module that forgot its own guard.
import ../../../src/protocols/dac/level0/defaults
import ../../../src/protocols/ame/level3/dac_relay
var
  R = initAmeDacRelay(cleanLanDacDefaults(), 7'u64, capacity = 2)
doAssert ameDacRelayLive(R) == 0
