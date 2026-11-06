## -------------------------------------------------------------------------
## Archive <- everything Bifrost offers for data that is STORED, in one import
## -------------------------------------------------------------------------
##
##   import protocols/archive
##
##   file                         job
##   ---------------------------  ---------------------------------------------
##   archive/types                the objects and every size
##   archive/level0/records       byte layouts: settings, headers, positions
##   archive/level1/keys          password -> login keys; master -> sub keys;
##                                FOMKE tight key -> space secret -> epoch key
##   archive/level1/sealed        one value sealed under key + label + place
##   archive/level1/log           one log record of a space, stored once
##   archive/level2/account       the master key record and space entries
##
## No database, no server, no socket: who stores the bytes and who may fetch
## them is decided elsewhere (Nebel's boxes). docs/chat-archive.md explains
## the whole design with every byte.

import ./archive/types as archive_types
import ./archive/level0/records as archive_records
import ./archive/level1/keys as archive_keys
import ./archive/level1/sealed as archive_sealed
import ./archive/level1/log as archive_log
import ./archive/level2/account as archive_account

export archive_types
export archive_records
export archive_keys
export archive_sealed
export archive_log
export archive_account
