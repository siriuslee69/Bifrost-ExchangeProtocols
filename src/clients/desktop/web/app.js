const messages = document.getElementById("messages");
const peerHost = document.getElementById("peer-host");
const body = document.getElementById("message-body");
const sendButton = document.getElementById("send-button");
const statusPill = document.getElementById("status-pill");
const localAddress = document.getElementById("local-address");
let hasMessages = false;

function bridgeFunction() {
  return window.bifrostInterop ||
    (window.webui && window.webui.bifrostInterop && window.webui.bifrostInterop.bind(window.webui)) ||
    (window.webui && window.webui.call && ((value) => window.webui.call("bifrostInterop", value)));
}

async function callBridge(request) {
  const fn = bridgeFunction();
  if (!fn) return { ok: false, error: "desktop bridge unavailable" };
  try {
    return JSON.parse(await fn(JSON.stringify(request)));
  } catch (error) {
    return { ok: false, error: String(error) };
  }
}

function addMessage(event) {
  if (!hasMessages) {
    messages.replaceChildren();
    hasMessages = true;
  }
  const row = document.createElement("article");
  const direction = event.error ? "error" : event.direction;
  row.className = `message ${direction}${event.ack ? " ack" : ""}`;
  const meta = document.createElement("span");
  meta.className = "message-meta";
  meta.textContent = `${event.direction.toUpperCase()} / ${event.peer}`;
  const content = document.createElement("div");
  content.className = "message-body";
  content.textContent = event.body;
  row.append(meta, content);
  messages.append(row);
  messages.scrollTop = messages.scrollHeight;
}

async function refreshStatus() {
  const reply = await callBridge({ op: "status" });
  statusPill.textContent = reply.ok ? "LISTENING" : "OFFLINE";
  localAddress.textContent = reply.address || "unavailable";
}

async function pollEvents() {
  const reply = await callBridge({ op: "events" });
  if (reply.ok && Array.isArray(reply.events)) reply.events.forEach(addMessage);
}

async function send() {
  const text = body.value.trim();
  if (!text) return;
  sendButton.disabled = true;
  await callBridge({ op: "send", host: peerHost.value.trim(), body: text });
  body.value = "";
  sendButton.disabled = false;
  body.focus();
  await pollEvents();
}

sendButton.addEventListener("click", send);
body.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    send();
  }
});
document.getElementById("clear-button").addEventListener("click", () => {
  messages.replaceChildren();
  hasMessages = false;
});

refreshStatus();
pollEvents();
setInterval(pollEvents, 350);
