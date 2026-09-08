## -------------------------------------------------------------------------
## Analysis Pragmas <- the one name Bifrost files import for their pragmas
## -------------------------------------------------------------------------
##
## The definitions themselves live in `meta/metaPragmas.nim`, which is the
## shared template every repository copies. This file exists for one reason,
## and it is not style:
##
##   Tyr ships `meta/metaPragmas.nim` too, and Bifrost compiles Tyr's sources
##   directly, so BOTH `meta` directories sit on the Nim path at once. A file
##   here writing `import metaPragmas` can therefore pick up TYR's copy --
##   whose `MetaTag` list is a different repository's -- and fail on a tag it
##   has never heard of.
##
##   Importing through this file names the path instead of the module, so the
##   right one is reached every time.
##
## Do not delete this and flatten the imports. It has been tried; the error
## it produces is `undeclared identifier: 'tagCryptoBoundary'`, several files
## away from the cause.

import ../meta/metaPragmas

export metaPragmas
