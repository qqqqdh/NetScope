"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const mock = new URLSearchParams(location.search).get("mock") === "1";
  const severityText = { high: "높음", medium: "보통", low: "낮음" };
  const alertTypes = {
    port_scan: "포트 스캔", syn_flood: "SYN 플러드",
    service_connectivity_issue: "서비스 연결 장애",
    dns_flood: "DNS 폭주", traffic_spike: "트래픽 급증"
  };
  const reasonLabels = {
    queue_drop: "패킷 손실", backlog: "처리 지연",
    late_drop: "늦은 패킷 폐기", future_drop: "시계 오차",
    flow_eviction: "Flow 축출", edge_untracked: "엣지 상한",
    detector_eviction: "탐지 상태 축출", unidirectional: "단방향 캡처",
    memory_high: "메모리 높음"
  };
  const state = {
    socket: null, reconnectTimer: null, reconnectDelay: 1000,
    hadConnection: false, lastAlertId: 0, alertIds: new Set(),
    alerts: [], snapshot: null, status: null, busy: false,
    trafficChart: null, protocolChart: null, simulation: null,
    nodeMap: new Map(), nodeSelection: null, edgeSelection: null,
    svg: null, graphLayer: null, zoom: null, mockTimer: null,
    mockTick: 0, mockAlertId: 0, selectedIp: null
  };

  function numeric(value) {
    const n = Number(value);
    return Number.isFinite(n) ? Math.max(0, n) : 0;
  }
  function formatBytes(value) {
    let n = numeric(value);
    const units = ["B", "KB", "MB", "GB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? Math.round(n).toString() : n.toFixed(n >= 100 ? 0 : 1)) + " " + units[i];
  }
  function formatRate(bytesPerSec) {
    let n = numeric(bytesPerSec) * 8;
    const units = ["bps", "kbps", "Mbps", "Gbps"];
    let i = 0;
    while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
    return (i === 0 ? Math.round(n).toString() : n.toFixed(n >= 100 ? 0 : 1)) + " " + units[i];
  }
  function formatClock(seconds) {
    const date = new Date(Number(seconds) * 1000);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString("ko-KR", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function formatDateTime(seconds) {
    const date = new Date(Number(seconds) * 1000);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("ko-KR", { hour12: false });
  }
  function protocolColor(name, alpha) {
    let hash = 2166136261;
    for (const char of String(name)) {
      hash ^= char.codePointAt(0);
      hash = Math.imul(hash, 16777619);
    }
    const hue = (hash >>> 0) % 360;
    return "hsla(" + hue + ", 75%, 62%, " + (alpha === undefined ? 1 : alpha) + ")";
  }
  function protocolLabel(name, item) {
    return String(name) + (item && item.estimated ? " (추정)" : "");
  }
  function setConnection(label, kind) {
    const el = $("connectionStatus");
    el.className = "connection-status " + kind;
    el.querySelector("span").textContent = label;
  }
  function toast(message, severity) {
    const el = document.createElement("div");
    el.className = "toast " + (severity || "");
    el.textContent = message;
    $("toastRegion").prepend(el);
    window.setTimeout(() => el.remove(), 4000);
  }
  function setStatus(status) {
    if (!status || typeof status !== "object") return;
    state.status = status;
    const badge = $("modeBadge");
    const mode = String(status.mode || "").toLowerCase();
    badge.className = "mode-badge " + (["live", "pcap"].includes(mode) ? mode : "");
    badge.textContent = mode ? mode.toUpperCase() : "—";
    $("pps").textContent = Math.round(numeric(status.pps)).toLocaleString("ko-KR");
    $("sourceToggle").disabled = state.busy;
    $("sourceToggle").textContent = status.source_running ? "일시정지" : "재개";
  }
  async function fetchStatus() {
    if (mock) return;
    try {
      const response = await fetch("/api/status", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      setStatus(await response.json());
    } catch (_) {
      if (!state.status) $("sourceToggle").disabled = true;
    }
  }
  async function toggleSource() {
    if (state.busy || !state.status) return;
    state.busy = true;
    $("sourceToggle").disabled = true;
    if (mock) {
      const running = !state.status.source_running;
      setStatus(Object.assign({}, state.status, { source_running: running }));
      if (running) startMockTimer();
      else stopMockTimer();
      state.busy = false;
      setStatus(state.status);
      return;
    }
    try {
      const endpoint = state.status.source_running ? "stop" : "start";
      const response = await fetch("/api/source/" + endpoint, { method: "POST" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      await fetchStatus();
      if (!state.status || state.status.source_running === (endpoint === "stop")) {
        setStatus(Object.assign({}, state.status || {}, { source_running: endpoint === "start" }));
      }
    } catch (error) {
      toast("소스 상태를 변경하지 못했습니다: " + error.message, "high");
    } finally {
      state.busy = false;
      if (state.status) setStatus(state.status);
    }
  }

  function initCharts() {
    if (!window.Chart) {
      toast("차트 라이브러리를 불러오지 못했습니다.", "high");
      return;
    }
    Chart.defaults.color = "#91a9bd";
    Chart.defaults.font.family = 'system-ui, "Malgun Gothic", sans-serif';
    state.trafficChart = new Chart($("trafficChart"), {
      type: "line",
      data: { labels: [], datasets: [] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (ctx) => ctx.dataset.label + ": " + formatBytes(ctx.parsed.y) } }
        },
        elements: { point: { radius: 0, hitRadius: 5 }, line: { borderWidth: 1.5, tension: 0.25 } },
        scales: {
          x: { stacked: true, grid: { color: "#283e522e" }, ticks: { maxTicksLimit: 7, maxRotation: 0 } },
          y: { stacked: true, beginAtZero: true, grid: { color: "#34506a55" }, ticks: { callback: (v) => formatBytes(v) } }
        }
      }
    });
    state.protocolChart = new Chart($("protocolChart"), {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0, hoverOffset: 5 }] },
      options: {
        animation: false, responsive: true, maintainAspectRatio: false, cutout: "72%",
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => ctx.label + ": " + formatBytes(ctx.parsed),
              afterLabel: (ctx) => {
                const name = ctx.chart.$protocolNames && ctx.chart.$protocolNames[ctx.dataIndex];
                const item = state.snapshot && state.snapshot.protocols && state.snapshot.protocols[name];
                if (!item || !item.estimated) return "";
                const percent = numeric(item.bytes) ? Math.round(numeric(item.low_confidence_bytes) / numeric(item.bytes) * 100) : 0;
                return "포트 기반 추정 · 낮은 신뢰도 " + percent + "%";
              }
            }
          }
        }
      }
    });
  }
  function updateCharts(snapshot) {
    const ts = snapshot.timeseries || {};
    const series = ts.series || {};
    const protocolItems = snapshot.protocols || {};
    const labels = Array.isArray(ts.labels) ? ts.labels.map(formatClock) : [];
    if (state.trafficChart) {
      state.trafficChart.data.labels = labels;
      state.trafficChart.data.datasets = Object.keys(series).sort().map((name) => ({
        label: protocolLabel(name, protocolItems[name]),
        data: (Array.isArray(series[name]) ? series[name] : []).map(numeric),
        borderColor: protocolColor(name),
        backgroundColor: protocolColor(name, 0.65),
        fill: true
      }));
      state.trafficChart.update("none");
    }
    const names = Object.keys(protocolItems).sort((a, b) => numeric(protocolItems[b].bytes) - numeric(protocolItems[a].bytes));
    if (state.protocolChart) {
      state.protocolChart.$protocolNames = names;
      state.protocolChart.data.labels = names.map((name) => protocolLabel(name, protocolItems[name]));
      state.protocolChart.data.datasets[0].data = names.map((name) => numeric(protocolItems[name].bytes));
      state.protocolChart.data.datasets[0].backgroundColor = names.map((name) => protocolColor(name));
      state.protocolChart.update("none");
    }
    const legend = $("protocolLegend");
    legend.replaceChildren();
    if (!names.length) {
      const empty = document.createElement("span");
      empty.className = "empty"; empty.textContent = "데이터 대기 중"; legend.append(empty);
    }
    names.forEach((name) => {
      const row = document.createElement("div");
      row.className = "legend-item";
      const dot = document.createElement("i");
      dot.className = "legend-swatch";
      dot.style.backgroundColor = protocolColor(name);
      const title = document.createElement("span");
      title.className = "legend-name";
      title.textContent = protocolLabel(name, protocolItems[name]);
      const value = document.createElement("span");
      value.className = "legend-value";
      value.textContent = formatBytes(protocolItems[name].bytes);
      row.append(dot, title, value);
      legend.append(row);
    });
  }

  function renderHealth(health) {
    const root = $("healthBadges");
    root.replaceChildren();
    const reasons = health && Array.isArray(health.reasons) ? health.reasons : [];
    if (!reasons.length) {
      const normal = document.createElement("span");
      normal.className = "health-normal";
      normal.textContent = "데이터 품질 정상";
      root.append(normal);
      return;
    }
    reasons.forEach((reason) => {
      const badge = document.createElement("span");
      badge.className = "health-badge";
      badge.textContent = reasonLabels[reason.code] || reason.code;
      badge.title = (reason.hint || "상세 안내 없음") + " · " + numeric(reason.count).toLocaleString("ko-KR") + "회";
      root.append(badge);
    });
  }
  function renderTables(graph) {
    const talkers = Array.isArray(graph.top_talkers) ? graph.top_talkers : [];
    const talkerBody = $("talkerRows");
    talkerBody.replaceChildren();
    if (!talkers.length) appendEmptyRow(talkerBody, 4, "통신 호스트 없음");
    talkers.forEach((node) => {
      const row = document.createElement("tr");
      appendCell(row, node.id);
      const scope = document.createElement("td");
      const label = document.createElement("span");
      label.className = "scope-label" + (node.local ? "" : " external");
      label.textContent = node.local ? "내부" : "외부";
      scope.append(label); row.append(scope);
      appendCell(row, formatBytes(node.bytes));
      appendCell(row, numeric(node.peers).toLocaleString("ko-KR"));
      talkerBody.append(row);
    });
    const candidates = Array.isArray(graph.approx_heavy_hitters) ? graph.approx_heavy_hitters : [];
    $("candidatePanel").hidden = candidates.length === 0;
    document.querySelector(".table-grid").classList.toggle("single", candidates.length === 0);
    const candidateBody = $("candidateRows");
    candidateBody.replaceChildren();
    if (!candidates.length) appendEmptyRow(candidateBody, 3, "후보 없음");
    candidates.forEach((edge) => {
      const row = document.createElement("tr");
      appendCell(row, edge.source);
      appendCell(row, edge.target);
      appendCell(row, "≈ " + formatBytes(edge.est_bytes) + " (오차 ≤ " + formatBytes(edge.error) + ")");
      candidateBody.append(row);
    });
  }
  function appendCell(row, text) {
    const cell = document.createElement("td");
    cell.textContent = text == null ? "—" : String(text);
    row.append(cell);
  }
  function appendEmptyRow(body, span, text) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = span; cell.className = "empty"; cell.textContent = text;
    row.append(cell); body.append(row);
  }

  function alertIp(alert) {
    if (!alert || alert.key === "global") return null;
    const key = String(alert.key || "");
    if (alert.type === "syn_flood" || alert.type === "service_connectivity_issue") {
      const cut = key.lastIndexOf(":");
      return cut >= 0 ? key.slice(0, cut).replace(/^\[|\]$/g, "") : key;
    }
    return key;
  }
  function recentAlertIps() {
    const end = state.snapshot ? numeric(state.snapshot.end) : Date.now() / 1000;
    return new Set(state.alerts.filter((a) => numeric(a.ts) >= end - 60 && numeric(a.ts) <= end + 1).map(alertIp).filter(Boolean));
  }
  function markAlertNodes() {
    if (!state.nodeSelection) return;
    const recent = recentAlertIps();
    state.nodeSelection.classed("alerted", (d) => recent.has(d.id))
      .classed("selected", (d) => d.id === state.selectedIp);
  }
  function addAlert(alert, notify) {
    if (!alert || !Number.isInteger(Number(alert.id))) return;
    const id = Number(alert.id);
    if (state.alertIds.has(id) || (state.alerts.length >= 200 && id < Number(state.alerts[state.alerts.length - 1].id))) return;
    state.alertIds.add(id);
    state.alerts.push(alert);
    state.alerts.sort((a, b) => Number(b.id) - Number(a.id));
    while (state.alerts.length > 200) {
      const removed = state.alerts.pop();
      state.alertIds.delete(Number(removed.id));
    }
    state.lastAlertId = Math.max(state.lastAlertId, id);
    renderAlerts();
    markAlertNodes();
    if (notify) toast((alertTypes[alert.type] || alert.type) + " · " + alert.message, alert.severity);
  }
  function renderAlerts() {
    $("alertCount").textContent = state.alerts.length.toLocaleString("ko-KR");
    $("alertHeadingCount").textContent = state.alerts.length.toLocaleString("ko-KR");
    const list = $("alertList");
    const expanded = new Set(Array.from(list.querySelectorAll(".alert-card.open")).map((el) => el.dataset.id));
    list.replaceChildren();
    if (!state.alerts.length) {
      const empty = document.createElement("p");
      empty.className = "empty"; empty.textContent = "수신된 경고가 없습니다.";
      list.append(empty);
      return;
    }
    const fragment = document.createDocumentFragment();
    state.alerts.forEach((alert) => {
      const card = document.createElement("div");
      card.className = "alert-card " + (["high", "medium", "low"].includes(alert.severity) ? alert.severity : "low");
      if (expanded.has(String(alert.id))) card.classList.add("open");
      card.dataset.id = String(alert.id);
      card.tabIndex = 0;
      card.setAttribute("role", "button");
      card.setAttribute("aria-expanded", card.classList.contains("open") ? "true" : "false");
      const top = document.createElement("div"); top.className = "alert-top";
      const type = document.createElement("span"); type.className = "alert-type";
      const sev = document.createElement("span"); sev.className = "severity-tag";
      sev.textContent = severityText[alert.severity] || "낮음";
      type.append(sev, document.createTextNode(alertTypes[alert.type] || alert.type || "경고"));
      const time = document.createElement("time"); time.className = "alert-time";
      time.textContent = formatDateTime(alert.ts);
      top.append(type, time);
      const message = document.createElement("p"); message.className = "alert-message";
      message.textContent = alert.message || "내용 없음";
      const meta = document.createElement("div"); meta.className = "alert-meta";
      const confidence = document.createElement("span");
      confidence.textContent = "신뢰도 " + (severityText[alert.confidence] || "알 수 없음");
      meta.append(confidence);
      const details = document.createElement("pre"); details.className = "alert-details";
      details.textContent = JSON.stringify(alert.details || {}, null, 2);
      card.append(top, message, meta, details);
      const open = () => {
        card.classList.toggle("open");
        card.setAttribute("aria-expanded", card.classList.contains("open") ? "true" : "false");
        const ip = alertIp(alert);
        if (ip) centerNode(ip);
      };
      card.addEventListener("click", open);
      card.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
      });
      fragment.append(card);
    });
    list.append(fragment);
  }

  function endpointId(endpoint) {
    return typeof endpoint === "object" ? endpoint.id : endpoint;
  }
  function initGraph() {
    if (!window.d3) {
      toast("그래프 라이브러리를 불러오지 못했습니다.", "high");
      return;
    }
    state.svg = d3.select("#connectionGraph");
    state.graphLayer = state.svg.append("g");
    state.graphLayer.append("g").attr("class", "edges");
    state.graphLayer.append("g").attr("class", "nodes");
    state.zoom = d3.zoom().scaleExtent([0.35, 6]).on("zoom", (event) => state.graphLayer.attr("transform", event.transform));
    state.svg.call(state.zoom);
    const box = $("connectionGraph").getBoundingClientRect();
    state.svg.call(state.zoom.transform, d3.zoomIdentity.translate(box.width / 2, box.height / 2));
    state.simulation = d3.forceSimulation([])
      .force("link", d3.forceLink([]).id((d) => d.id).distance(85).strength(0.25))
      .force("charge", d3.forceManyBody().strength(-140))
      .force("center", d3.forceCenter(0, 0))
      .force("collision", d3.forceCollide().radius((d) => d.radius + 10))
      .on("tick", () => {
        if (state.edgeSelection) state.edgeSelection
          .attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
          .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
        if (state.nodeSelection) state.nodeSelection.attr("transform", (d) => "translate(" + d.x + "," + d.y + ")");
      });
    window.addEventListener("resize", () => {
      if (state.simulation) state.simulation.alpha(0.1).restart();
    });
  }
  function showGraphTooltip(event, node) {
    const stage = document.querySelector(".graph-stage");
    const rect = stage.getBoundingClientRect();
    const tip = $("graphTooltip");
    tip.textContent = node.id + "\n범위: " + (node.scope || "—") +
      "\n통신량: " + formatBytes(node.bytes) + "\n상대 IP: " + numeric(node.peers).toLocaleString("ko-KR");
    tip.hidden = false;
    tip.style.left = Math.min(event.clientX - rect.left + 12, rect.width - tip.offsetWidth - 8) + "px";
    tip.style.top = Math.min(event.clientY - rect.top + 12, rect.height - tip.offsetHeight - 8) + "px";
  }
  function hideGraphTooltip() { $("graphTooltip").hidden = true; }
  function centerNode(ip) {
    state.selectedIp = ip;
    markAlertNodes();
    if (!state.svg || !state.nodeMap.has(ip)) return;
    const node = state.nodeMap.get(ip);
    const box = $("connectionGraph").getBoundingClientRect();
    const current = d3.zoomTransform(state.svg.node());
    const scale = Math.max(1.5, current.k);
    state.svg.transition().duration(500).call(
      state.zoom.transform,
      d3.zoomIdentity.translate(box.width / 2 - node.x * scale, box.height / 2 - node.y * scale).scale(scale)
    );
  }
  function updateGraph(graph) {
    const other = numeric(graph.other && graph.other.bytes);
    $("graphOther").hidden = other <= 0;
    $("graphOther").textContent = "기타 연결 트래픽: " + formatBytes(other);
    $("graphLowerBound").hidden = !graph.edges_lower_bound;
    renderTables(graph);
    if (!state.simulation) return;
    const incoming = Array.isArray(graph.nodes) ? graph.nodes : [];
    const incomingIds = new Set(incoming.map((d) => String(d.id)));
    for (const id of state.nodeMap.keys()) if (!incomingIds.has(id)) state.nodeMap.delete(id);
    const maxBytes = Math.max(1, ...incoming.map((d) => numeric(d.bytes)));
    incoming.forEach((item) => {
      const id = String(item.id);
      let node = state.nodeMap.get(id);
      if (!node) {
        const angle = Math.random() * Math.PI * 2;
        const radius = 50 + Math.random() * 95;
        node = { id, x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
        state.nodeMap.set(id, node);
      }
      Object.assign(node, item);
      node.id = id;
      node.radius = 5 + 16 * Math.sqrt(numeric(item.bytes) / maxBytes);
    });
    const nodes = Array.from(state.nodeMap.values());
    const edges = (Array.isArray(graph.edges) ? graph.edges : []).filter((e) =>
      state.nodeMap.has(String(endpointId(e.source))) && state.nodeMap.has(String(endpointId(e.target))))
      .map((e) => Object.assign({}, e, { source: String(endpointId(e.source)), target: String(endpointId(e.target)) }));
    const maxEdgeBytes = Math.max(1, ...edges.map((e) => numeric(e.bytes)));
    state.edgeSelection = state.graphLayer.select(".edges").selectAll("line.edge")
      .data(edges, (d) => String(endpointId(d.source)) + "|" + String(endpointId(d.target)))
      .join("line").attr("class", "edge")
      .attr("stroke", (d) => {
        const entries = Object.entries(d.protocols || {});
        entries.sort((a, b) => numeric(b[1]) - numeric(a[1]));
        return protocolColor(entries.length ? entries[0][0] : "기타");
      })
      .attr("stroke-width", (d) => 0.7 + 4.5 * Math.log1p(numeric(d.bytes)) / Math.log1p(maxEdgeBytes));
    state.nodeSelection = state.graphLayer.select(".nodes").selectAll("g.node")
      .data(nodes, (d) => d.id)
      .join(
        (enter) => {
          const group = enter.append("g").attr("class", "node");
          group.append("circle").attr("class", "pulse");
          group.append("circle").attr("class", "core");
          group.append("text").attr("x", 10).attr("y", 3);
          return group;
        },
        (update) => update,
        (exit) => exit.remove()
      )
      .classed("external", (d) => !d.local)
      .call(d3.drag()
        .on("start", (event, d) => { if (!event.active) state.simulation.alphaTarget(0.15).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event, d) => { if (!event.active) state.simulation.alphaTarget(0); d.fx = null; d.fy = null; }))
      .on("mousemove", showGraphTooltip)
      .on("mouseleave", hideGraphTooltip)
      .on("click", (event, d) => { event.stopPropagation(); centerNode(d.id); });
    state.nodeSelection.select(".core").attr("r", (d) => d.radius)
      .attr("fill", (d) => d.local ? "#4aaeff" : "#ffae6b");
    state.nodeSelection.select(".pulse").attr("r", (d) => d.radius + 5);
    state.nodeSelection.select("text").attr("x", (d) => d.radius + 5).text((d) => d.id);
    markAlertNodes();
    $("graphEmpty").hidden = nodes.length > 0;
    state.simulation.nodes(nodes);
    state.simulation.force("link").links(edges);
    state.simulation.alpha(0.3).restart();
  }

  function applySnapshot(snapshot) {
    if (!snapshot || typeof snapshot !== "object") return;
    state.snapshot = snapshot;
    if (snapshot.status) setStatus(snapshot.status);
    $("bandwidth").textContent = formatRate(snapshot.rate && snapshot.rate.bytes_per_sec);
    $("flows").textContent = numeric(snapshot.flows && snapshot.flows.active).toLocaleString("ko-KR");
    $("totalBytes").textContent = formatBytes(snapshot.totals && snapshot.totals.bytes);
    $("snapshotTime").textContent = "기준 " + formatDateTime(snapshot.end) + " · " + numeric(snapshot.window || 60) + "초 창";
    renderHealth(snapshot.health);
    updateCharts(snapshot);
    updateGraph(snapshot.graph || {});
  }
  function receiveSnapshot(message, socket) {
    const seq = Number(message.seq);
    if (!Number.isInteger(seq)) return;
    try {
      applySnapshot(message.data);
    } catch (error) {
      console.error("스냅샷 적용 실패", error);
      return;
    }
    requestAnimationFrame(() => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "ack", seq: seq }));
      }
    });
  }
  function alertArray(value) {
    if (Array.isArray(value)) return value;
    if (value && Array.isArray(value.alerts)) return value.alerts;
    if (value && Array.isArray(value.data)) return value.data;
    return [];
  }
  async function recoverAlerts(sinceId) {
    try {
      const response = await fetch("/api/alerts?since_id=" + encodeURIComponent(sinceId), { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      for (const alert of alertArray(await response.json())) addAlert(alert, false);
    } catch (error) {
      toast("누락 경고 복구 실패: " + error.message, "medium");
    }
  }
  function scheduleReconnect() {
    if (state.reconnectTimer) return;
    const delay = state.reconnectDelay;
    setConnection("재연결 " + (delay / 1000) + "초 후", "disconnected");
    state.reconnectTimer = window.setTimeout(() => {
      state.reconnectTimer = null;
      connectWebSocket();
    }, delay);
    state.reconnectDelay = Math.min(10000, delay * 2);
  }
  function connectWebSocket() {
    setConnection("연결 중", "");
    const url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";
    let socket;
    try { socket = new WebSocket(url); }
    catch (_) { scheduleReconnect(); return; }
    state.socket = socket;
    socket.addEventListener("open", () => {
      if (state.socket !== socket) return;
      const reconnect = state.hadConnection;
      const sinceId = state.lastAlertId;
      state.hadConnection = true;
      state.reconnectDelay = 1000;
      setConnection("연결됨", "connected");
      fetchStatus();
      if (reconnect) recoverAlerts(sinceId);
    });
    socket.addEventListener("message", (event) => {
      if (state.socket !== socket) return;
      let message;
      try { message = JSON.parse(event.data); } catch (_) { return; }
      if (message.type === "hello") {
        if (message.data && message.data.status) setStatus(message.data.status);
        for (const alert of alertArray(message.data && message.data.alerts)) addAlert(alert, false);
      } else if (message.type === "snapshot") receiveSnapshot(message, socket);
      else if (message.type === "alert") addAlert(message.data, true);
    });
    socket.addEventListener("close", () => {
      if (state.socket !== socket) return;
      state.socket = null;
      scheduleReconnect();
    });
    socket.addEventListener("error", () => {
      if (state.socket === socket) setConnection("연결 오류", "disconnected");
    });
  }

  function makeMockSnapshot(tick) {
    const end = Math.floor(Date.now() / 1000);
    const names = ["HTTPS", "HTTP", "DNS", "SSH", "TCP", "UDP"];
    const base = [62000, 22000, 9500, 5500, 15500, 11000];
    const labels = Array.from({ length: 60 }, (_, i) => end - 59 + i);
    const series = {};
    const protocols = {};
    names.forEach((name, j) => {
      const values = labels.map((_, i) => Math.max(0, Math.round(base[j] * (0.66 + 0.24 * Math.sin((tick + i) / (5 + j)) + Math.random() * 0.5))));
      const bytes = values.reduce((a, b) => a + b, 0);
      series[name] = values;
      protocols[name] = {
        packets: Math.round(bytes / 850), bytes, estimated_bytes: Math.round(bytes * 0.95),
        low_confidence_bytes: Math.round(bytes * (j % 3 === 0 ? 0.2 : 0.07)),
        estimated: j < 4
      };
    });
    const nodes = Array.from({ length: 30 }, (_, i) => ({
      id: i < 10 ? "192.168.1." + (10 + i) : "203.0.113." + (i + 10),
      bytes: Math.round(150000 + (30 - i) * 36000 * (0.8 + Math.random() * 0.4)),
      packets: 200 + i * 7, peers: i < 10 ? 7 : 2,
      local: i < 10, scope: i < 10 ? "rfc1918" : "documentation"
    }));
    const edges = [];
    for (let i = 10; i < nodes.length; i++) {
      const target = i % 10;
      const bytes = Math.round(100000 + Math.random() * 450000);
      const proto = names[i % names.length];
      edges.push({ source: nodes[target].id, target: nodes[i].id, bytes, packets: Math.round(bytes / 850), protocols: { [proto]: bytes } });
      if (i % 3 === 0) edges.push({ source: nodes[(target + 3) % 10].id, target: nodes[i].id, bytes: Math.round(bytes / 3), packets: 100, protocols: { DNS: Math.round(bytes / 3) } });
    }
    const totalBytes = Object.values(protocols).reduce((sum, item) => sum + item.bytes, 0);
    const currentRate = names.reduce((sum, name) => sum + series[name][59], 0);
    const status = { mode: "sim", source_running: state.status ? state.status.source_running : true, pps: Math.round(currentRate / 850), uptime: tick, queue_size: 3, clients: 1 };
    return {
      end, window: 60, totals: { packets: Math.round(totalBytes / 850), bytes: totalBytes },
      rate: { bytes_per_sec: currentRate }, protocols,
      timeseries: { labels, series },
      graph: {
        start: end - 59, end, nodes, edges,
        total: { packets: Math.round(totalBytes / 850), bytes: totalBytes },
        other: { packets: 290, bytes: 232000 + tick % 10 * 10000 },
        edges_lower_bound: tick % 18 < 5,
        approx_heavy_hitters: [
          { source: nodes[2].id, target: nodes[20].id, est_bytes: 12800000, error: 1100000 },
          { source: nodes[3].id, target: nodes[25].id, est_bytes: 4200000, error: 370000 }
        ],
        top_talkers: nodes.slice().sort((a, b) => b.bytes - a.bytes).slice(0, 8)
      },
      health: { degraded: tick % 18 < 5, reasons: tick % 18 < 5 ? [{ code: "edge_untracked", count: 12, first_ts: end - 4, last_ts: end, hint: "일부 연결은 기타 트래픽으로 합산됩니다." }] : [], totals: {} },
      flows: { active: 74 + tick % 20, evictions: 0, tcp_flows: 66, tcp_bidirectional: 60 },
      buffered: 0, status
    };
  }
  function mockStep() {
    state.mockTick++;
    applySnapshot(makeMockSnapshot(state.mockTick));
    if (state.mockTick % 9 === 0) {
      const types = ["port_scan", "syn_flood", "dns_flood", "traffic_spike", "service_connectivity_issue"];
      const type = types[Math.floor(state.mockTick / 9) % types.length];
      const key = type === "traffic_spike" ? "global" :
        type === "syn_flood" || type === "service_connectivity_issue" ? "192.168.1.12:443" : "192.168.1.12";
      addAlert({
        id: ++state.mockAlertId, ts: Math.floor(Date.now() / 1000), type, key,
        severity: type === "syn_flood" ? "high" : type === "traffic_spike" ? "low" : "medium",
        confidence: "medium", message: (alertTypes[type] || type) + " 징후가 관측되었습니다.",
        details: { source: key, sample_count: 80 + state.mockTick, window_seconds: 10 }
      }, true);
    }
  }
  function stopMockTimer() {
    if (state.mockTimer) clearInterval(state.mockTimer);
    state.mockTimer = null;
  }
  function startMockTimer() {
    if (state.mockTimer) return;
    mockStep();
    state.mockTimer = setInterval(mockStep, 1000);
  }

  $("sourceToggle").addEventListener("click", toggleSource);
  initCharts();
  initGraph();
  if (mock) {
    setConnection("목업 실행 중", "connected");
    setStatus({ mode: "sim", source_running: true, pps: 0, uptime: 0, queue_size: 0, clients: 1 });
    startMockTimer();
  } else {
    fetchStatus();
    connectWebSocket();
  }
})();
