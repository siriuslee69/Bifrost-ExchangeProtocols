## --------------------------------------------------------------
## HTTP <- HTTP/1.1 server protocol facade for Bifrost transports
## --------------------------------------------------------------
##
## One import gives the whole server-side HTTP/1.1 surface:
##
##   import protocols/http
##
##   var
##     C = initHttpServerConnection()
##     outcome = feedHttpConnection(C, requestBytes)
##   if outcome.events[0].kind == hekRequest:
##     discard respondHttpConnection(C, textResponse(200, "hi"))
##
## Nothing here opens a socket. `level2/server_connection` turns bytes
## into requests and responses back into bytes; carrying those bytes is
## the caller's job, which is what lets the same code sit behind plain
## TCP or behind the `tls13` session.
##
## Layout:
##   types.nim                 <- request/response shapes, limits
##   level0/header_ops.nim     <- case-insensitive fields, strict checks
##   level0/target_ops.nim     <- decode + normalise the request path
##   level1/chunked_ops.nim    <- chunked body codec
##   level1/request_parser.nim <- incremental request reader
##   level1/response_ops.nim   <- status phrases, head serialisation
##   level2/server_connection  <- keep-alive connection state machine

import ./http/types
import ./http/level0/[header_ops, target_ops]
import ./http/level1/[chunked_ops, request_parser, response_ops]
import ./http/level2/server_connection

export types
export header_ops
export target_ops
export chunked_ops
export request_parser
export response_ops
export server_connection
