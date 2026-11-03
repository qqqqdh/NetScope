"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const mock = new URLSearchParams(location.search).get("mock") === "1";
  const types = { port_scan: "포트 스캔", syn_flood: "SYN 플러드", dns_flood: "DNS 폭주",
    traffic_spike: "트래픽 급증", service_connectivity_issue: "서비스 연결 장애" };
  const severities = { low: "낮음", medium: "보통", high: "높음" };
  function bytes(value) {
    let n = Number(value) || 0, i = 0;
    const units = ["B", "KB", "MB", "GB"];
    while (n >= 1024 && i < 3) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : Math.round(n)) + " " + units[i];
  }
  function date(value) { return new Date(value * 1000).toLocaleString("ko-KR", { hour12: false }); }
  function row(values, tag = "td") {
    const tr = document.createElement("tr");
    values.forEach((value) => {
      const cell = document.createElement(tag);
      cell.textContent = value;
      tr.append(cell);
    });
    return tr;
  }
  function empty(body, columns, message) {
    const tr = row([message]);
    tr.firstChild.colSpan = columns;
    tr.firstChild.className = "empty";
    body.replaceChildren(tr);
  }
  async function get(url) {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error("조회 실패 (HTTP " + response.status + ")");
    return response.json();
  }
  let processBusy = false;
  async function processes() {
    if (processBusy || mock) return;
    processBusy = true;
    try {
      const data = await get("/api/processes");
      const body = $("processRows");
      body.replaceChildren();
      if (!data.enabled) {
        $("processNote").textContent = "LIVE 모드에서 사용할 수 있습니다. 시뮬레이션·PCAP은 현재 PC의 프로세스와 대응하지 않습니다.";
        empty(body, 5, "실제 캡처를 시작하면 프로그램별 통신량이 표시됩니다.");
        return;
      }
      $("processNote").textContent = data.error ||
        "이번 실행에서 수집한 패킷 기준 누적값 · 연결 표를 1초마다 대조합니다. 짧은 연결·공유 소켓 등은 누락될 수 있습니다. 대응 " +
        bytes(data.matched_bytes) + " / 미확인 " + bytes(data.unmatched_bytes) + " (헤더 포함)";
      data.items.forEach((item) => body.append(row([item.name, item.pid, bytes(item.sent_bytes), bytes(item.received_bytes), item.connections])));
      if (!data.items.length) empty(body, 5, "대응된 패킷이 없습니다. 브라우저 등에서 통신을 발생시켜 보세요.");
    } catch (error) {
      $("processNote").textContent = "프로세스 정보 " + error.message;
      empty($("processRows"), 5, "최신 프로세스 정보를 확인할 수 없습니다.");
    } finally { processBusy = false; }
  }
  let historyRequest = 0;
  async function history() {
    if (mock) return;
    const request = ++historyRequest;
    const kind = $("historyKind").value, mode = $("historyMode").value;
    const query = new URLSearchParams({ kind, limit: "50" });
    if (mode) query.set("mode", mode);
    const download = new URLSearchParams(query);
    download.set("format", "csv"); download.set("limit", "10000");
    $("historyDownload").href = "/api/history?" + download;
    const stats = kind === "stats";
    const columns = stats ? ["기록 시각", "모드 / 실행", "이벤트 시각", "최근 60초 통신량", "속도", "활성 Flow", "큐 손실 / 품질"] :
      ["기록 시각", "모드 / 실행", "탐지 시각", "유형", "심각도", "내용"];
    $("historyHead").replaceChildren(row(columns, "th"));
    try {
      const status = await get("/api/status");
      if (request !== historyRequest) return;
      if (!status.history || !status.history.enabled) {
        $("historyNote").textContent = "이력 저장이 꺼져 있습니다. --history netscope-history.sqlite3 옵션으로 다시 실행하세요.";
        $("historyDownload").hidden = true;
        empty($("historyRows"), columns.length, "저장된 이력을 조회하려면 저장 기능을 켜세요.");
        return;
      }
      const data = await get("/api/history?" + query);
      if (request !== historyRequest) return;
      $("historyDownload").hidden = false;
      $("historyNote").textContent = data.error ||
        "통계는 약 10초마다, 경고는 발생할 때 저장합니다. 최근 7일 · 통계 최대 10만 / 경고 1만 건. 최신 50건 표시, CSV는 최대 1만 건. 60초 통신량은 중복 구간이므로 합산하지 마세요.";
      if (data.dropped) $("historyNote").textContent += " 저장 누락: " + data.dropped + "건.";
      const body = $("historyRows");
      body.replaceChildren();
      data.items.forEach((item) => {
        const base = [date(item.recorded_at), item.mode.toUpperCase() + " / " + item.session.slice(0, 6)];
        body.append(row(stats ? base.concat([date(item.event_time), bytes(item.window_bytes), bytes(item.bytes_per_sec) + "/s", item.active_flows,
          item.queue_drops + " / " + (item.degraded ? "주의" : "정상")]) :
          base.concat([date(item.ts), types[item.type] || item.type, severities[item.severity] || item.severity, item.message])));
      });
      if (!data.items.length) empty(body, columns.length, "해당 조건의 저장 기록이 없습니다.");
    } catch (error) {
      if (request !== historyRequest) return;
      $("historyNote").textContent = "이력 " + error.message;
      $("historyDownload").hidden = true;
      empty($("historyRows"), columns.length, "최신 이력을 확인할 수 없습니다.");
    }
  }
  $("historyRefresh").addEventListener("click", history);
  $("historyKind").addEventListener("change", history);
  $("historyMode").addEventListener("change", history);
  if (mock) {
    $("processNote").textContent = "목업에서는 실제 프로세스를 조회하지 않습니다.";
    $("historyNote").textContent = "목업에서는 이력을 저장하거나 조회하지 않습니다.";
    $("historyDownload").hidden = true;
    ["historyKind", "historyMode", "historyRefresh"].forEach((id) => { $(id).disabled = true; });
  } else {
    processes(); history();
    setInterval(processes, 3000);
    setInterval(history, 10000);
  }
})();
