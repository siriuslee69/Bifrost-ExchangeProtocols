package com.siriuslee.bifrost.android

import android.content.Context
import android.os.Build
import java.util.UUID

object NodeIdentity {
  private const val PREFS = "bifrost_node"
  private const val KEY_ID = "node_id"

  fun load(context: Context): LocalNode {
    val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    var nodeId = prefs.getString(KEY_ID, null)
    if (nodeId.isNullOrBlank()) {
      nodeId = UUID.randomUUID().toString()
      prefs.edit().putString(KEY_ID, nodeId).apply()
    }
    val suffix = nodeId.take(4).uppercase()
    val model = Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android"
    return LocalNode(nodeId = nodeId, displayName = "$model-$suffix")
  }
}
