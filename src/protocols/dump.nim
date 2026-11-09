## -------------------------------------------------------------------------
## Dump <- where received messages wait until they are safely on a disk
## -------------------------------------------------------------------------
##
##   import protocols/dump
##
##   var D = initDumpBuffer()
##   discard D.offerDump(DumpRecord(stream: "chat/7", sender: "alice", body: msg))
##   var batch = D.grabDump()
##   # ... write batch.records to disk ...
##   discard D.settleDump(batch.ticket)   # or giveBackDump, when the write failed
##
##   file                  job
##   --------------------  -----------------------------------------------
##   dump/types            the objects and limits
##   dump/level0/records   a record and the cursors as bytes
##   dump/level1/buffer    offer, grab, settle, give back

import ./dump/types as dump_types
import ./dump/level0/records as dump_records
import ./dump/level1/buffer as dump_buffer

export dump_types
export dump_records
export dump_buffer
