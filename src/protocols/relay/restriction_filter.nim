## -------------------------------------------------------------------------
## Restriction filter <- one check for the list-based modes
## -------------------------------------------------------------------------
##
## The relay (per connection) and the super-fast relay (one operator list)
## both decide with the same call. Neither needs AME, so this module imports
## only the types, the address form, and the two list modes.
##
## Def. 1: filterAllows(mode, F, src) is the answer of one list set F for a
## sender at address src. rmGroup is not a list, so it always answers false
## here; the group mode is decided by restriction.nim from the group object.

import runePragmas
import ./restriction_types
import ./restriction_address
import ./restriction_listed
import ./restriction_allowed

proc filterAllows*(mode: RestrictionMode, F: SourceRules, src: SourceAddr): bool {.
    role: parser.} =
  ## mode/F/src: the answer for one frame. A mode not compiled in refuses.
  case mode
  of rmOpen:
    result = true
  of rmListed:
    when restrictionListedBuilt:
      result = listedAllows(F, src)
    else:
      result = false
  of rmAllowed:
    when restrictionAllowedBuilt:
      result = allowedAllows(F, src)
    else:
      result = false
  of rmGroup:
    result = false
