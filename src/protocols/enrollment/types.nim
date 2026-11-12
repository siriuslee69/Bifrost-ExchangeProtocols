## -------------------------------------------------------------------------
## Enrollment types <- the shapes of group admission
## -------------------------------------------------------------------------
##
## Def. 1 (enroller): ONE AME authority key whose signature admits a public
##   key into a group. Its public half is pinned in the roster.
## Def. 2 (enrollment): the enroller's signed admission of one member key into
##   one group, with a serial and a validity window.
## Def. 3 (roster): the enroller pin + a predefined key list + operator-added
##   keys. A key is a member when it is in either list, or holds a valid
##   enrollment.
##
##   GroupRoster
##   ---------------------------------
##   enroller:   AmeAuthorityRoot      the one public key that may enroll
##   predefined: [keyId, ...]          admitted without a token (config)
##   added:      [keyId, ...]          the operator added these by hand
##
## A member is named by ameIdentityKeyId (32 hex characters of its public
## keys), never by a name it chose for itself.

import ../types
import ../ame/types
import runePragmas

const
  enrollmentVersion*: uint8 = 1'u8
    ## The first byte of an enrollment token and of a saved roster.
  enrollmentLabel* = "GROUP-ENROLL-v1"
    ## The domain label in front of everything the enroller signs.
  enrollmentKeyIdChars* = 32
    ## ameIdentityKeyId: 16 bytes written as 32 hex characters.
  enrollmentMaxGroupBytes* = 255
    ## Longest group name one admission may carry.
  enrollmentMaxKeys* = 4096
    ## Most keys one roster list keeps: a stranger must not grow it for ever.
  enrollmentMaxProofs* = ameMaxAlgorithmSlots
    ## One proof per enroller slot, and no more slots than AME has.

type
  GroupEnrollment* {.role: truthState, tag: "enrollment",
      expectedCount: [0, 4096], lifeCycle: lcSession.} = object
    ## One enroller-signed admission of a member key into a group (Def. 2).
    group*: string
    memberKeyId*: string
      ## ameIdentityKeyId of the member's public keys.
    serial*: uint64
      ## Names this admission; revoking a serial takes one enrollment out of
      ## use without burning the member's key.
    validFromUnix*: int64
    validUntilUnix*: int64
    proofs*: seq[ByteSeq]
      ## One proof per enroller slot, in the enroller's own key order. Empty
      ## means "no token presented".

  GroupRoster* {.role: truthState, tag: "enrollment",
      expectedCount: 1, lifeCycle: lcForever.} = object
    ## Who may be a member (Def. 3). One enroller pin and two key lists.
    enroller*: AmeAuthorityRoot
    predefined*: seq[string]
      ## Key ids admitted without a token; set once, not edited by the CLI.
    added*: seq[string]
      ## Key ids the operator added by hand.