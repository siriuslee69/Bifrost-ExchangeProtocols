## This file should be imported across all files inside src.
## Keep the template pragma names stable. `wrapper` and `stateController`
## remain as compatibility role names for older Bifrost modules.

type
  MetaRole* = enum
    helper, math,
    dataFetcher, decryptor, sanitizer, parser, truthBuilder, metaParser,
    actor, orchestrator, metaOrchestrator, encryptor, dataWriter,
    configurator, rawData, preparedData, truthState, memory,
    otherRole,
    wrapper, stateController, other

  MetaInput* = enum
    user, llm, thirdParty, trusted

  MetaRisk* = enum
    low, medium, high

  MetaSpeed* = enum
    fast, normal, long, dataDependent

  MetaIssue* = tuple
    name: string
    id: uint64

  MetaIssues* = seq[MetaIssue]

  MetaTag* = enum
    tagOther,
    tagAme,
    tagAppApi,
    tagBfx1,
    tagBfx2,
    tagCodecBoundary,
    tagChunkyAead,
    tagCryptoBoundary,
    tagDocs,
    tagExchange,
    tagFomke,
    tagFormatting,
    tagGgAead,
    tagGeoJson,
    tagInterop,
    tagKdf,
    tagNetworkSurface,
    tagOrchestrator,
    tagPacket,
    tagParsing,
    tagProtocol,
    tagRead,
    tagRegistry,
    tagStateController,
    tagTcp,
    tagTls,
    tagTmeAead,
    tagTransport,
    tagTypes,
    tagUdp,
    tagValidation,
    tagWrite

  MetaTags* = set[MetaTag]

template input*(x: MetaInput) {.pragma.}
template input*(x: set[MetaInput]) {.pragma.}
template role*(x: MetaRole) {.pragma.}
template role*(x: set[MetaRole]) {.pragma.}
template risk*(x: MetaRisk) {.pragma.}
template speed*(x: MetaSpeed) {.pragma.}
template issue*(x: MetaIssue) {.pragma.}
template issues*(x: MetaIssues) {.pragma.}
template tag*(x: MetaTags) {.pragma.}
template metaTags*(x: MetaTags) {.pragma.}
