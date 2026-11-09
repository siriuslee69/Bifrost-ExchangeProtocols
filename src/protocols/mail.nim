## ------------------------------------------------------------
## Mail <- Bifrost's protocol surface for mail, no socket anywhere
## ------------------------------------------------------------

import ./mail/dkim_crypto
import ./mail/message
import ./mail/dns_mx

export dkim_crypto
export message
export dns_mx
