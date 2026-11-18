## -------------------------------------------------------------------------
## SMTP <- how mail servers talk, as bytes in and bytes out, no socket
## -------------------------------------------------------------------------
##
##   file                 job
##   -------------------  ------------------------------------------------
##   smtp/types           the objects and limits
##   smtp/level0/lines    one command, one reply, one address, dot-stuffing
##   smtp/level1/server   the receiving side
##   smtp/level1/client   the sending side of one delivery
##   smtp/level2/server_tls  the receiving side with STARTTLS (TLS 1.3). Import it on
##                        its own: it pulls the TLS code in, which plain SMTP does not need
##
## `mail/message.nim` signs a mail (DKIM); `mail/dns_mx.nim` asks which server
## takes mail for a domain. The sockets are Nebel's (nebel-maild).

import ./smtp/types as smtp_types
import ./smtp/level0/lines as smtp_lines
import ./smtp/level1/server as smtp_server
import ./smtp/level1/client as smtp_client

export smtp_types
export smtp_lines
export smtp_server
export smtp_client
