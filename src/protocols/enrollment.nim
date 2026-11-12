## -------------------------------------------------------------------------
## Enrollment <- one enroller key admits public keys into groups, one import
## -------------------------------------------------------------------------
##
##   import protocols/enrollment
##
##   file                       job
##   -------------------------  ---------------------------------------------
##   enrollment/types           GroupEnrollment, GroupRoster, every limit
##   enrollment/level0/token    the enroller-signed admission: issue, verify,
##                              encode, decode
##   enrollment/level1/roster   membership (predefined / operator-added /
##                              enrolled), add/remove key, roster codec
##
## The enroller is an AME authority key and a member is an AME identity named
## by ameIdentityKeyId, so this reuses the existing identity and signature
## stack rather than a second key system. No disk, no socket: keeping the
## roster bytes is the caller's business (the operator CLI, or Nebel).

import ./enrollment/types as enrollment_types
import ./enrollment/level0/token as enrollment_token
import ./enrollment/level1/roster as enrollment_roster

export enrollment_types
export enrollment_token
export enrollment_roster