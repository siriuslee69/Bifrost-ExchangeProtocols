package com.siriuslee.bifrost.android

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.LinkedHashMap
import java.util.Locale

class MainActivity : Activity(), BifrostNode.Listener {
  private lateinit var node: BifrostNode
  private lateinit var peerList: LinearLayout
  private lateinit var messageList: LinearLayout
  private lateinit var messageScroll: ScrollView
  private lateinit var messageInput: EditText
  private lateinit var hostInput: EditText
  private lateinit var statusText: TextView
  private lateinit var protocolText: TextView
  private lateinit var root: FrameLayout

  private val main = Handler(Looper.getMainLooper())
  private val peers = LinkedHashMap<String, PeerEndpoint>()
  private val logs = ArrayDeque<BifrostLogEntry>()
  private val timeFormat = SimpleDateFormat("HH:mm", Locale.US)
  private var selectedPeerId: String? = null
  private var selectedProtocol = ProtocolKind.TCP

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    node = BifrostNode(applicationContext, this)
    buildUi()
    node.start()
    statusText.text = "${node.local.displayName}  ${node.localAddressSummary()}"
  }

  override fun onDestroy() {
    node.stop()
    super.onDestroy()
  }

  override fun onPeer(peer: PeerEndpoint) {
    main.post {
      peers[peer.nodeId] = peer
      if (selectedPeerId == null) selectedPeerId = peer.nodeId
      renderPeers()
    }
  }

  override fun onLog(entry: BifrostLogEntry) {
    main.post {
      logs.addLast(entry)
      while (logs.size > 180) logs.removeFirst()
      renderMessages()
    }
  }

  private fun buildUi() {
    root = FrameLayout(this).apply {
      background = GradientDrawable(
        GradientDrawable.Orientation.TL_BR,
        intArrayOf(paletteDeepBlue, paletteVoid, palettePlumVoid),
      )
      setOnApplyWindowInsetsListener { _, insets ->
        val bars = insets.getInsets(WindowInsets.Type.systemBars())
        setPadding(dp(10), bars.top + dp(8), dp(10), bars.bottom + dp(8))
        insets
      }
    }
    root.addView(signalGrid(), FrameLayout.LayoutParams(match(), match()))

    val shell = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
    }
    shell.addView(topPanel(), LinearLayout.LayoutParams(match(), dp(58)).bottom(dp(7)))
    shell.addView(peerPanel(), LinearLayout.LayoutParams(match(), wrap()).bottom(dp(7)))
    shell.addView(conversationPanel(), LinearLayout.LayoutParams(match(), 0, 1f).bottom(dp(7)))
    shell.addView(composerPanel(), LinearLayout.LayoutParams(match(), wrap()))
    root.addView(shell, FrameLayout.LayoutParams(match(), match()))
    setContentView(root)
  }

  private fun signalGrid(): View =
    object : View(this) {
      private val paint = android.graphics.Paint().apply {
        color = Color.argb(18, 167, 251, 255)
        strokeWidth = 1f
      }

      override fun onDraw(canvas: android.graphics.Canvas) {
        super.onDraw(canvas)
        val step = dp(42).toFloat()
        var x = 0f
        var y = 0f
        while (x < width) {
          canvas.drawLine(x, 0f, x, height.toFloat(), paint)
          x += step
        }
        while (y < height) {
          canvas.drawLine(0f, y, width.toFloat(), y, paint)
          y += step
        }
      }
    }

  private fun topPanel(): View {
    val panel = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
      background = panelDrawable(paletteCyan)
      setPadding(dp(12), 0, dp(12), 0)
    }
    panel.addView(badge("B", paletteCyan), LinearLayout.LayoutParams(dp(34), dp(34)))
    val copy = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(dp(12), 0, 0, 0)
    }
    copy.addView(label("DIRECT SIGNAL", 9f, paletteMuted, 0.14f))
    copy.addView(label("BIFROST LAN", 18f, paletteText, 0.10f, true))
    panel.addView(copy, LinearLayout.LayoutParams(0, wrap(), 1f))
    statusText = label("starting", 9f, paletteCyanHot, 0.04f).apply {
      gravity = Gravity.END
      maxLines = 2
    }
    panel.addView(statusText, LinearLayout.LayoutParams(dp(145), wrap()))
    return panel
  }

  private fun peerPanel(): View {
    val panel = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      background = panelDrawable(paletteBlue)
      setPadding(dp(8), dp(7), dp(8), dp(7))
    }
    val row = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
    }
    hostInput = EditText(this).apply {
      hint = "peer ip"
      setHintTextColor(paletteMuted)
      setTextColor(paletteText)
      setSingleLine(true)
      inputType = InputType.TYPE_CLASS_TEXT
      background = inputDrawable(paletteCyan)
      setPadding(dp(9), 0, dp(9), 0)
      typeface = Typeface.MONOSPACE
      textSize = 12f
    }
    row.addView(hostInput, LinearLayout.LayoutParams(0, dp(40), 1f))
    row.addView(actionButton("+") { addManualPeer() }, LinearLayout.LayoutParams(dp(44), dp(40)).left(dp(5)))
    panel.addView(row, LinearLayout.LayoutParams(match(), wrap()).bottom(dp(5)))
    peerList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    panel.addView(peerList, LinearLayout.LayoutParams(match(), wrap()))
    renderPeers()
    return panel
  }

  private fun conversationPanel(): View {
    val panel = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      background = panelDrawable(paletteMagenta)
    }
    val head = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
      setPadding(dp(12), 0, dp(12), 0)
      background = fill(Color.argb(90, 6, 11, 17))
    }
    head.addView(label("MACHINE / MOTOROLA", 13f, paletteText, 0.08f, true), LinearLayout.LayoutParams(0, wrap(), 1f))
    protocolText = label("TCP  LIVE", 10f, paletteGreen, 0.10f, true).apply {
      setOnClickListener { cycleProtocol() }
      setPadding(dp(9), dp(7), dp(9), dp(7))
      background = thinDrawable(paletteGreen)
    }
    head.addView(protocolText)
    panel.addView(head, LinearLayout.LayoutParams(match(), dp(48)))
    messageScroll = ScrollView(this).apply {
      isFillViewport = true
      overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
    }
    messageList = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.BOTTOM
      setPadding(dp(12), dp(12), dp(12), dp(12))
    }
    messageScroll.addView(messageList, ViewGroup.LayoutParams(match(), wrap()))
    panel.addView(messageScroll, LinearLayout.LayoutParams(match(), 0, 1f))
    renderMessages()
    return panel
  }

  private fun composerPanel(): View {
    val panel = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER_VERTICAL
      background = panelDrawable(paletteCyan)
      setPadding(dp(7), dp(6), dp(7), dp(6))
    }
    messageInput = EditText(this).apply {
      hint = "write a direct message"
      setHintTextColor(paletteMuted)
      setTextColor(paletteText)
      minLines = 1
      maxLines = 3
      background = inputDrawable(paletteMagenta)
      setPadding(dp(10), dp(7), dp(10), dp(7))
    }
    panel.addView(messageInput, LinearLayout.LayoutParams(0, wrap(), 1f))
    panel.addView(actionButton("SEND >") { sendMessage() }, LinearLayout.LayoutParams(dp(92), dp(44)).left(dp(6)))
    return panel
  }

  private fun addManualPeer() {
    try {
      val peer = node.addManualPeer(hostInput.text.toString())
      selectedPeerId = peer.nodeId
      renderPeers()
    } catch (t: Throwable) {
      onLog(BifrostLogEntry(System.currentTimeMillis(), ProtocolKind.SYSTEM, LogDirection.ERROR, "local", t.message ?: "bad host"))
    }
  }

  private fun sendMessage() {
    val peer = selectedPeer()
    if (peer == null) {
      onLog(BifrostLogEntry(System.currentTimeMillis(), ProtocolKind.SYSTEM, LogDirection.ERROR, "local", "select or add a peer"))
      return
    }
    val body = messageInput.text.toString().trim()
    if (body.isEmpty()) return
    node.send(selectedProtocol, peer, body)
    messageInput.text.clear()
  }

  private fun cycleProtocol() {
    val order = listOf(ProtocolKind.TCP, ProtocolKind.UDP, ProtocolKind.TLS)
    val index = (order.indexOf(selectedProtocol) + 1) % order.size
    selectedProtocol = order[index]
    protocolText.text = "${selectedProtocol.label}  LIVE"
    protocolText.setTextColor(protocolColor(selectedProtocol))
    protocolText.background = thinDrawable(protocolColor(selectedProtocol))
  }

  private fun selectedPeer(): PeerEndpoint? =
    selectedPeerId?.let { peers[it] } ?: peers.values.firstOrNull()

  private fun renderPeers() {
    if (!::peerList.isInitialized) return
    peerList.removeAllViews()
    if (peers.isEmpty()) {
      peerList.addView(label("waiting for LAN discovery or add an IP", 10f, paletteMuted, 0.02f).apply {
        gravity = Gravity.CENTER
        setPadding(0, dp(6), 0, dp(6))
      })
      return
    }
    for (peer in peers.values.sortedByDescending { it.lastSeenMillis }.take(3)) {
      val selected = selectedPeerId == peer.nodeId
      val row = label("${if (selected) ">" else " "} ${peer.displayName}  ${peer.host}", 11f, if (selected) paletteCyanHot else paletteText, 0.02f).apply {
        typeface = Typeface.MONOSPACE
        background = if (selected) thinDrawable(paletteMagenta) else fill(Color.argb(20, 109, 199, 221))
        setPadding(dp(7), dp(7), dp(7), dp(7))
        setOnClickListener {
          selectedPeerId = peer.nodeId
          renderPeers()
        }
      }
      peerList.addView(row, LinearLayout.LayoutParams(match(), wrap()).bottom(dp(3)))
    }
  }

  private fun renderMessages() {
    if (!::messageList.isInitialized) return
    messageList.removeAllViews()
    val visible = logs.filter { it.direction == LogDirection.IN || it.direction == LogDirection.OUT || it.direction == LogDirection.ERROR }.takeLast(80)
    if (visible.isEmpty()) {
      val empty = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
      }
      empty.addView(badge("B", paletteCyan), LinearLayout.LayoutParams(dp(40), dp(40)).bottom(dp(14)))
      empty.addView(label("Channel ready", 14f, paletteText, 0.02f, true))
      empty.addView(label("Messages remain on your local network.", 10f, paletteMuted, 0.01f))
      messageList.addView(empty, LinearLayout.LayoutParams(match(), dp(210)))
      return
    }
    for (entry in visible) messageList.addView(messageBubble(entry), LinearLayout.LayoutParams(match(), wrap()).bottom(dp(8)))
    messageScroll.post { messageScroll.fullScroll(View.FOCUS_DOWN) }
  }

  private fun messageBubble(entry: BifrostLogEntry): View {
    val outgoing = entry.direction == LogDirection.OUT
    val error = entry.direction == LogDirection.ERROR
    val accent = when {
      error -> paletteDanger
      outgoing -> paletteMagenta
      else -> paletteCyan
    }
    val row = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = if (outgoing) Gravity.END else if (error) Gravity.CENTER else Gravity.START
    }
    row.addView(label("${timeFormat.format(Date(entry.timestampMillis))}  ${entry.peer}  ${entry.protocol.label}", 9f, paletteMuted, 0.02f).apply {
      typeface = Typeface.MONOSPACE
    })
    row.addView(label(entry.message, 12f, if (error) paletteDanger else paletteText, 0f).apply {
      maxWidth = (resources.displayMetrics.widthPixels * 0.76f).toInt()
      background = bubbleDrawable(accent, outgoing)
      setPadding(dp(10), dp(8), dp(10), dp(8))
    }, LinearLayout.LayoutParams(wrap(), wrap()).top(dp(3)))
    return row
  }

  private fun label(textValue: String, size: Float, color: Int, spacing: Float, bold: Boolean = false): TextView =
    TextView(this).apply {
      text = textValue
      textSize = size
      setTextColor(color)
      letterSpacing = spacing
      typeface = if (bold) Typeface.create("sans-serif-condensed", Typeface.BOLD) else Typeface.DEFAULT
      includeFontPadding = false
    }

  private fun badge(value: String, accent: Int): TextView =
    label(value, 15f, paletteInk, 0f, true).apply {
      gravity = Gravity.CENTER
      background = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        setColor(accent)
        cornerRadius = dp(1).toFloat()
      }
      rotation = 45f
      setShadowLayer(8f, 0f, 0f, Color.argb(150, Color.red(accent), Color.green(accent), Color.blue(accent)))
    }

  private fun actionButton(value: String, action: () -> Unit): TextView =
    label(value, 11f, paletteCyanHot, 0.08f, true).apply {
      gravity = Gravity.CENTER
      background = thinDrawable(paletteCyan)
      setOnClickListener { action() }
    }

  private fun panelDrawable(accent: Int): GradientDrawable =
    GradientDrawable().apply {
      setColor(Color.argb(202, 9, 16, 23))
      setStroke(dp(1), Color.argb(90, Color.red(accent), Color.green(accent), Color.blue(accent)))
      cornerRadius = dp(1).toFloat()
    }

  private fun inputDrawable(accent: Int): GradientDrawable =
    GradientDrawable().apply {
      setColor(Color.argb(175, 5, 10, 15))
      setStroke(dp(1), Color.argb(105, Color.red(accent), Color.green(accent), Color.blue(accent)))
      cornerRadius = dp(1).toFloat()
    }

  private fun thinDrawable(accent: Int): GradientDrawable =
    GradientDrawable().apply {
      setColor(Color.argb(30, Color.red(accent), Color.green(accent), Color.blue(accent)))
      setStroke(dp(1), Color.argb(110, Color.red(accent), Color.green(accent), Color.blue(accent)))
      cornerRadius = dp(1).toFloat()
    }

  private fun bubbleDrawable(accent: Int, outgoing: Boolean): GradientDrawable =
    GradientDrawable().apply {
      setColor(Color.argb(38, Color.red(accent), Color.green(accent), Color.blue(accent)))
      setStroke(dp(2), Color.argb(170, Color.red(accent), Color.green(accent), Color.blue(accent)))
      cornerRadii = if (outgoing) floatArrayOf(dp(2f), dp(2f), 0f, 0f, 0f, 0f, dp(2f), dp(2f)) else floatArrayOf(0f, 0f, dp(2f), dp(2f), dp(2f), dp(2f), 0f, 0f)
    }

  private fun fill(color: Int): GradientDrawable = GradientDrawable().apply { setColor(color) }
  private fun protocolColor(protocol: ProtocolKind): Int = when (protocol) {
    ProtocolKind.TCP -> paletteCyan
    ProtocolKind.TLS -> paletteMagenta
    ProtocolKind.UDP -> paletteGreen
    ProtocolKind.AME -> paletteGold
    else -> paletteText
  }

  private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
  private fun dp(value: Float): Float = value * resources.displayMetrics.density
  private fun match(): Int = ViewGroup.LayoutParams.MATCH_PARENT
  private fun wrap(): Int = ViewGroup.LayoutParams.WRAP_CONTENT

  private fun LinearLayout.LayoutParams.bottom(value: Int) = apply { bottomMargin = value }
  private fun LinearLayout.LayoutParams.left(value: Int) = apply { leftMargin = value }
  private fun LinearLayout.LayoutParams.top(value: Int) = apply { topMargin = value }

  private companion object {
    val paletteVoid = Color.rgb(7, 10, 15)
    val paletteDeepBlue = Color.rgb(20, 39, 50)
    val palettePlumVoid = Color.rgb(29, 13, 31)
    val paletteInk = Color.rgb(7, 16, 24)
    val paletteText = Color.rgb(244, 247, 251)
    val paletteMuted = Color.rgb(164, 175, 188)
    val paletteCyan = Color.rgb(109, 199, 221)
    val paletteCyanHot = Color.rgb(167, 251, 255)
    val paletteMagenta = Color.rgb(214, 86, 156)
    val paletteBlue = Color.rgb(71, 132, 202)
    val paletteGreen = Color.rgb(92, 214, 143)
    val paletteGold = Color.rgb(255, 209, 120)
    val paletteDanger = Color.rgb(255, 123, 138)
  }
}
