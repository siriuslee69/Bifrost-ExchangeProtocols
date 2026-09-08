## ---------------------------------------------------------------------
## BFX2 GeoJSON <- minimal GeoJSON validation + packet/envelope helpers
## ---------------------------------------------------------------------

import std/json

import ../types
import ./types
import ./writer
import ./reader
import bifrostPragmas

const
  bfxGeoJsonErrRootNotObject* = "bfx2/geojson: root must be an object"
  bfxGeoJsonErrTypeMissing* = "bfx2/geojson: missing string field 'type'"
  bfxGeoJsonErrUnsupportedType* = "bfx2/geojson: unsupported geojson type"
  bfxGeoJsonErrCoordinatesMissing* = "bfx2/geojson: missing array field 'coordinates'"
  bfxGeoJsonErrFeaturesInvalid* = "bfx2/geojson: feature collection requires array field 'features'"
  bfxGeoJsonErrGeometriesInvalid* = "bfx2/geojson: geometry collection requires array field 'geometries'"
  bfxGeoJsonErrFeatureGeometryInvalid* = "bfx2/geojson: feature requires object|null field 'geometry'"
  bfxGeoJsonErrFeaturePropertiesInvalid* = "bfx2/geojson: feature properties must be object|null"
  bfxGeoJsonErrInvalidNestedGeometry* = "bfx2/geojson: invalid nested geometry"

proc hasArrayField(n: JsonNode, k: string): bool {.gcsafe, role: helper.} =
  ## hasArrayField: build has array field.
  if not n.hasKey(k):
    return false
  result = n[k].kind == JArray

proc typeName(n: JsonNode): tuple[ok: bool, name: string] {.gcsafe, role: helper.} =
  ## typeName: build type name.
  if not n.hasKey("type"):
    return (false, "")
  if n["type"].kind != JString:
    return (false, "")
  result = (true, n["type"].getStr())

proc validateGeometryNode(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.}
  ## validateGeometryNode: validate geometry node.
proc validateGeoJsonNode*(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.}
  ## validateGeoJsonNode: validate geo JSON node.

proc validateGeometryCollection(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.} =
  ## validateGeometryCollection: validate geometry collection.
  var
    i: int = 0
    child: tuple[ok: bool, err: string]
  if not hasArrayField(n, "geometries"):
    return (false, bfxGeoJsonErrGeometriesInvalid)
  while i < n["geometries"].len:
    if n["geometries"][i].kind != JObject:
      return (false, bfxGeoJsonErrInvalidNestedGeometry)
    child = validateGeometryNode(n["geometries"][i])
    if not child.ok:
      return (false, bfxGeoJsonErrInvalidNestedGeometry)
    i.inc
  result = (true, "")

proc validateGeometryNode(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.} =
  ## validateGeometryNode: validate geometry node.
  var
    tn: tuple[ok: bool, name: string]
  tn = typeName(n)
  if not tn.ok:
    return (false, bfxGeoJsonErrTypeMissing)
  case tn.name
  of "Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon":
    if not hasArrayField(n, "coordinates"):
      return (false, bfxGeoJsonErrCoordinatesMissing)
    result = (true, "")
  of "GeometryCollection":
    result = validateGeometryCollection(n)
  else:
    result = (false, bfxGeoJsonErrUnsupportedType)

proc validateFeature(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.} =
  ## validateFeature: validate feature.
  var
    g: JsonNode
    gv: tuple[ok: bool, err: string]
  if not n.hasKey("geometry"):
    return (false, bfxGeoJsonErrFeatureGeometryInvalid)
  g = n["geometry"]
  if g.kind != JNull and g.kind != JObject:
    return (false, bfxGeoJsonErrFeatureGeometryInvalid)
  if g.kind == JObject:
    gv = validateGeometryNode(g)
    if not gv.ok:
      return (false, bfxGeoJsonErrFeatureGeometryInvalid)
  if n.hasKey("properties"):
    if n["properties"].kind != JObject and n["properties"].kind != JNull:
      return (false, bfxGeoJsonErrFeaturePropertiesInvalid)
  result = (true, "")

proc validateFeatureCollection(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.} =
  ## validateFeatureCollection: validate feature collection.
  var
    i: int = 0
    fv: tuple[ok: bool, err: string]
    tn: tuple[ok: bool, name: string]
  if not hasArrayField(n, "features"):
    return (false, bfxGeoJsonErrFeaturesInvalid)
  while i < n["features"].len:
    if n["features"][i].kind != JObject:
      return (false, bfxGeoJsonErrFeaturesInvalid)
    tn = typeName(n["features"][i])
    if not tn.ok or tn.name != "Feature":
      return (false, bfxGeoJsonErrFeaturesInvalid)
    fv = validateFeature(n["features"][i])
    if not fv.ok:
      return (false, bfxGeoJsonErrFeaturesInvalid)
    i.inc
  result = (true, "")

proc validateGeoJsonNode*(n: JsonNode): tuple[ok: bool, err: string] {.gcsafe, role: parser.} =
  ## Validate a GeoJSON object with minimal structural checks.
  var
    tn: tuple[ok: bool, name: string]
  if n.kind != JObject:
    return (false, bfxGeoJsonErrRootNotObject)
  tn = typeName(n)
  if not tn.ok:
    return (false, bfxGeoJsonErrTypeMissing)
  case tn.name
  of "Feature":
    result = validateFeature(n)
  of "FeatureCollection":
    result = validateFeatureCollection(n)
  of "Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon", "GeometryCollection":
    result = validateGeometryNode(n)
  else:
    result = (false, bfxGeoJsonErrUnsupportedType)

proc encodeGeoJsonPacket*(n: JsonNode): tuple[ok: bool, packet: ByteSeq, err: string] {.gcsafe, role: helper.} =
  ## Validate and encode GeoJSON as a BFX2 dynamic value packet.
  var
    v: tuple[ok: bool, err: string]
  v = validateGeoJsonNode(n)
  if not v.ok:
    return (false, @[], v.err)
  result = (true, encodeJsonNodePacket(n), "")

proc decodeGeoJsonPacket*(bs: ByteSeq): tuple[ok: bool, geoJson: JsonNode, err: string] {.gcsafe, role: parser.} =
  ## Decode a BFX2 dynamic value packet and validate GeoJSON structure.
  var
    d: tuple[ok: bool, node: JsonNode, err: string]
    v: tuple[ok: bool, err: string]
  d = decodeJsonNodePacket(bs)
  if not d.ok:
    return (false, newJNull(), d.err)
  v = validateGeoJsonNode(d.node)
  if not v.ok:
    return (false, newJNull(), v.err)
  result = (true, d.node, "")

proc encodeGeoJsonEnvelope*(
    schemaId: uint16;
    schemaVersion: uint16;
    n: JsonNode;
    flags: uint16 = bfxFlagChecksum
): tuple[ok: bool, packet: ByteSeq, err: string] {.gcsafe, role: helper.} =
  ## Validate + encode GeoJSON and wrap in a BFX2 envelope.
  var
    p: tuple[ok: bool, packet: ByteSeq, err: string]
  p = encodeGeoJsonPacket(n)
  if not p.ok:
    return (false, @[], p.err)
  result = (true, encodeBfxEnvelope(schemaId, schemaVersion, p.packet, flags), "")

proc decodeGeoJsonEnvelope*(bs: ByteSeq): tuple[
    ok: bool,
    header: BfxHeader,
    geoJson: JsonNode,
    err: string
] {.gcsafe, role: parser.} =
  ## Decode BFX2 envelope payload as GeoJSON packet.
  var
    d: tuple[ok: bool, header: BfxHeader, payload: ByteSeq, err: string]
    p: tuple[ok: bool, geoJson: JsonNode, err: string]
  d = decodeBfxEnvelope(bs)
  if not d.ok:
    return (false, BfxHeader(), newJNull(), d.err)
  p = decodeGeoJsonPacket(d.payload)
  if not p.ok:
    return (false, BfxHeader(), newJNull(), p.err)
  result = (true, d.header, p.geoJson, "")
