## ----------------------------------------------------------------------
## DAC Build <- one flag decides whether the adaptive layer exists at all
## ----------------------------------------------------------------------

import ../../analysis_pragmas

const
  dacBuildAscii* = """
Two independent flags, because they answer two different questions.

  -d:bifrostCarriers=   does AME speak the DAC datagram framing at all?
  -d:bifrostDac=off     is there an adaptive layer sitting on top of it?

  +-------------------------------------------------------------+
  | always compiled: frame envelope, body codecs, fixed profiles |
  +-------------------------------------------------------------+
  | -d:bifrostDac=off drops: link loop, ACK pacing, scrambling,  |
  |   package planning, Reed-Solomon repair, secure packages     |
  +-------------------------------------------------------------+

With the adaptive layer gone, AME still sends and receives DAC frames. It
simply runs on one fixed scenario profile forever instead of moving its own
parameters, which is what a sensor on a known link wants anyway.

What this flag is NOT: a size lever. Nim emits no code for a proc nothing
calls, so a build that never touches the link loop is already free of it.
The flag exists so that touching it is a COMPILE ERROR rather than a silent
inclusion -- if you declared the layer gone, reaching for it should fail
loudly. Eir also stays required either way, because AME compresses payloads
with Eir's RLE independently of anything DAC does.
"""

  bifrostDac* {.strdefine.}: string = ""

proc parseDacBuild(s: string): bool {.compileTime, role: parser.} =
  ## s: raw -d:bifrostDac= value.
  ## An unrecognised value is a compile error rather than a silent default,
  ## because quietly shipping the layer someone asked to remove is worse than
  ## refusing to build.
  case s
  of "", "on", "1", "yes", "full":
    result = true
  of "off", "0", "no", "none":
    result = false
  else:
    raise newException(ValueError,
      "-d:bifrostDac= accepts on or off, not '" & s & "'")

const
  dacAdaptiveBuilt* = parseDacBuild(bifrostDac)
    ## True when the link loop, ACK pacing, scrambling and package repair are
    ## part of this build.
