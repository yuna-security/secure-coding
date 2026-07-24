/* 채팅 클라이언트 (R3). CSP script-src 'self' 준수(외부 파일, 인라인 없음).
 * 보안: 수신 메시지는 textContent로만 렌더링해 XSS를 원천 차단한다.
 * 발신자 신원은 서버 세션이 결정하므로 클라이언트는 username을 보내지 않는다. */
(function () {
  "use strict";
  var root = document.getElementById("chat-root");
  if (!root) return;

  var scope = root.getAttribute("data-scope");
  var roomId = root.getAttribute("data-room-id");
  var log = document.getElementById("chat-log");
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var submit = form.querySelector("button[type='submit']");
  var errorBox = document.getElementById("chat-error");
  var meId = root.getAttribute("data-me-id");
  var ready = false;

  function setReady(value) {
    ready = value;
    input.disabled = !value;
    submit.disabled = !value;
  }

  function showError(text) {
    errorBox.textContent = text || "";
  }

  setReady(false);
  if (typeof io === "undefined") {
    showError("채팅 클라이언트를 불러오지 못했습니다.");
    return;
  }

  var socket = io({ transports: ["websocket", "polling"] });

  function pad(n) { return (n < 10 ? "0" : "") + n; }

  function appendMessage(msg) {
    var li = document.createElement("li");
    li.className = "chat-msg" + (msg.sender_id === meId ? " mine" : "");

    var user = document.createElement("span");
    user.className = "chat-user";
    user.textContent = msg.username;              // 안전 렌더링

    var text = document.createElement("span");
    text.className = "chat-text";
    text.textContent = msg.content;               // 안전 렌더링(HTML 해석 안 함)

    var time = document.createElement("span");
    time.className = "chat-time muted";
    var d = msg.created_at ? new Date(msg.created_at) : new Date();
    time.textContent = pad(d.getHours()) + ":" + pad(d.getMinutes());

    li.appendChild(user);
    li.appendChild(text);
    li.appendChild(time);
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
  }

  socket.on("connect", function () {
    showError("");
    if (scope === "dm" && roomId) {
      socket.emit("join_dm", { room_id: roomId });
    } else {
      setReady(true);
    }
  });

  socket.on("connect_error", function () {
    setReady(false);
    showError("연결에 실패했습니다. 로그인 상태를 확인하세요.");
  });

  socket.on("disconnect", function () {
    setReady(false);
    showError("채팅 연결이 종료되었습니다.");
  });

  socket.on("chat_error", function (data) {
    showError((data && data.error) || "오류가 발생했습니다.");
  });

  socket.on("dm_joined", function (data) {
    if (scope === "dm" && data && data.room_id === roomId) {
      showError("");
      setReady(true);
    }
  });

  if (scope === "global") {
    socket.on("global_message", function (msg) {
      if (msg && msg.scope === "global") appendMessage(msg);
    });
  } else if (scope === "dm") {
    socket.on("dm_message", function (msg) {
      if (msg && msg.scope === "dm" && msg.room_id === roomId) {
        appendMessage(msg);
      }
    });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!ready) return;
    var content = input.value.trim();
    if (!content) return;
    if (scope === "dm") {
      socket.emit("dm_message", { room_id: roomId, content: content });
    } else {
      socket.emit("global_message", { content: content });
    }
    input.value = "";
    input.focus();
  });

  // 초기 진입 시 히스토리 맨 아래로 스크롤.
  if (log) log.scrollTop = log.scrollHeight;
})();
