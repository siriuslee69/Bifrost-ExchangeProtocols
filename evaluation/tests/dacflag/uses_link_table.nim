## Uses the adaptive layer's link table. Must NOT build under -d:bifrostDac=off.
## Imported directly rather than through the umbrella, because the umbrella's
## `when` block would hide a module that forgot its own guard.
import ../../../src/protocols/dac/level0/defaults
import ../../../src/protocols/dac/level3/link_table
var
  T = initDacLinkTable(cleanLanDacDefaults(), 7'u64, capacity = 4)
doAssert dacLinkTableLive(T) == 0
doAssert admitDacLink(T, initDacLinkKey("10.0.0.1", 9000'u16), 1'u64, 1'u32,
  0'u32).admit == dlaAdmitted
