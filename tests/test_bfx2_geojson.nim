## --------------------------------------------------------
## BFX2 GeoJSON Tests <- geojson packet and envelope helpers
## --------------------------------------------------------

import std/[json, unittest]

import bifrost_exchange_protocols

suite "BFX2 GeoJSON":
  test "feature collection packet roundtrip":
    var
      g0: JsonNode
      enc: tuple[ok: bool, packet: ByteSeq, err: string]
      dec: tuple[ok: bool, geoJson: JsonNode, err: string]
    g0 = %*{
      "type": "FeatureCollection",
      "features": [
        {
          "type": "Feature",
          "properties": {"name": "alpha"},
          "geometry": {
            "type": "Point",
            "coordinates": [13.4050, 52.5200]
          }
        },
        {
          "type": "Feature",
          "properties": {"name": "lane"},
          "geometry": {
            "type": "LineString",
            "coordinates": [
              [7.0, 50.0],
              [8.0, 51.0]
            ]
          }
        }
      ]
    }
    enc = encodeGeoJsonPacket(g0)
    check enc.ok
    dec = decodeGeoJsonPacket(enc.packet)
    check dec.ok
    check dec.geoJson["type"].getStr() == "FeatureCollection"
    check dec.geoJson["features"].len == 2
    check dec.geoJson["features"][0]["geometry"]["type"].getStr() == "Point"

  test "feature with null geometry is valid":
    var
      g0: JsonNode
      v: tuple[ok: bool, err: string]
    g0 = %*{
      "type": "Feature",
      "properties": {"id": 12},
      "geometry": nil
    }
    v = validateGeoJsonNode(g0)
    check v.ok

  test "geojson envelope roundtrip":
    var
      g0: JsonNode
      enc: tuple[ok: bool, packet: ByteSeq, err: string]
      dec: tuple[ok: bool, header: BfxHeader, geoJson: JsonNode, err: string]
    g0 = %*{
      "type": "Point",
      "coordinates": [9.9937, 53.5511]
    }
    enc = encodeGeoJsonEnvelope(450'u16, 1'u16, g0, bfxFlagChecksum)
    check enc.ok
    dec = decodeGeoJsonEnvelope(enc.packet)
    check dec.ok
    check dec.header.schemaId == 450'u16
    check dec.geoJson["type"].getStr() == "Point"

  test "feature collection must provide features array":
    var
      bad: JsonNode
      v: tuple[ok: bool, err: string]
    bad = %*{
      "type": "FeatureCollection",
      "features": "nope"
    }
    v = validateGeoJsonNode(bad)
    check not v.ok
    check v.err == bfxGeoJsonErrFeaturesInvalid

  test "point geometry requires coordinates":
    var
      bad: JsonNode
      v: tuple[ok: bool, err: string]
    bad = %*{
      "type": "Point"
    }
    v = validateGeoJsonNode(bad)
    check not v.ok
    check v.err == bfxGeoJsonErrCoordinatesMissing

  test "feature collection rejects bare geometry entries":
    var
      bad: JsonNode
      v: tuple[ok: bool, err: string]
    bad = %*{
      "type": "FeatureCollection",
      "features": [
        {
          "type": "Point",
          "coordinates": [11.0, 48.0]
        }
      ]
    }
    v = validateGeoJsonNode(bad)
    check not v.ok
    check v.err == bfxGeoJsonErrFeaturesInvalid

  test "decode rejects non-geojson packet":
    var
      bs: ByteSeq
      dec: tuple[ok: bool, geoJson: JsonNode, err: string]
    bs = encodeJsonNodePacket(%*{"name": "alpha"})
    dec = decodeGeoJsonPacket(bs)
    check not dec.ok
    check dec.err == bfxGeoJsonErrTypeMissing
