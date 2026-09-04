(() => {
  const DATA = window.PQC_ROADMAP;
  const LANG_STORAGE_KEY = "doravota.pqc.lang.v2";
  const state = {
    lang: localStorage.getItem(LANG_STORAGE_KEY) || "en",
    curating: false,
    selected: null,
    current: null,
    status: {},
    playing: false,
    unfurled: false,
  };

  const $ = (sel) => document.querySelector(sel);
  const t = () => DATA.copy[state.lang];
  const allowedStatuses = new Set(["done", "live", "pending"]);
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let labelLayoutFrame = 0;
  let labelResizeObserver = null;

  function mergeKnownStatus(target, source) {
    if (!source || typeof source !== "object") return;
    for (const node of DATA.nodes) {
      if (allowedStatuses.has(source[node.id])) target[node.id] = source[node.id];
    }
  }

  function defaultStatus() {
    const map = {};
    for (const n of DATA.nodes) map[n.id] = n.status;
    return map;
  }

  function stageNumber(node) {
    return String(node?.stage || 0).padStart(2, "0");
  }

  function earlierStageNodes(id) {
    const node = nodeById(id);
    if (!node) return [];
    return DATA.nodes.filter((candidate) => candidate.stage < node.stage);
  }

  function laterStageNodes(id) {
    const node = nodeById(id);
    if (!node) return [];
    return DATA.nodes.filter((candidate) => candidate.stage > node.stage);
  }

  function canActivate(id) {
    return earlierStageNodes(id).every((node) => state.status[node.id] === "done");
  }

  function canReset(id) {
    return laterStageNodes(id).every((node) => state.status[node.id] === "pending");
  }

  function normalizeStatus(status) {
    const ordered = [...DATA.nodes].sort((a, b) => a.stage - b.stage || a.x - b.x);
    for (const node of ordered) {
      if (status[node.id] === "pending") continue;
      const blocked = DATA.nodes.some(
        (candidate) => candidate.stage < node.stage && status[candidate.id] !== "done"
      );
      if (blocked) status[node.id] = "pending";
    }
  }

  function loadStatus() {
    const base = defaultStatus();
    try {
      const saved = JSON.parse(localStorage.getItem(DATA.storageKey) || "null");
      mergeKnownStatus(base, saved);
    } catch (_) {}
    normalizeStatus(base);
    state.status = base;
    const savedCurrent = localStorage.getItem(`${DATA.storageKey}.current`);
    state.current = DATA.nodes.some((node) => node.id === savedCurrent) && base[savedCurrent] !== "pending"
      ? savedCurrent
      : null;
  }

  async function overlayRemoteProgress() {
    try {
      const res = await fetch("progress.json", { cache: "no-store" });
      if (!res.ok) return;
      if (localStorage.getItem(DATA.storageKey)) return;
      const remote = await res.json();
      if (remote && typeof remote === "object") {
        mergeKnownStatus(state.status, remote);
        normalizeStatus(state.status);
        render();
      }
    } catch (_) {}
  }

  function saveStatus() {
    localStorage.setItem(DATA.storageKey, JSON.stringify(state.status));
    if (state.current) localStorage.setItem(`${DATA.storageKey}.current`, state.current);
    else localStorage.removeItem(`${DATA.storageKey}.current`);
  }

  function nodeById(id) {
    return DATA.nodes.find((n) => n.id === id);
  }

  function preds(id) {
    return DATA.edges.filter(([, b]) => b === id).map(([a]) => a);
  }

  function descendants(id) {
    const found = new Set();
    const visit = (from) => {
      for (const [, to] of DATA.edges.filter(([source]) => source === from)) {
        if (found.has(to)) continue;
        found.add(to);
        visit(to);
      }
    };
    visit(id);
    return [...found];
  }

  function ancestorEdges(id) {
    const found = new Map();
    const visit = (to) => {
      for (const from of preds(to)) {
        const key = `${from}:${to}`;
        if (!found.has(key)) found.set(key, [from, to]);
        visit(from);
      }
    };
    visit(id);
    return [...found.values()];
  }

  function visibility(id) {
    const st = state.status[id];
    if (st === "done" || st === "live") return "revealed";
    return canActivate(id) ? "frontier" : "planned";
  }

  function counts() {
    const vals = Object.values(state.status);
    return {
      done: vals.filter((s) => s === "done").length,
      live: vals.filter((s) => s === "live").length,
      pending: vals.filter((s) => s === "pending").length,
      total: vals.length,
    };
  }

  function edgeKind(from, to) {
    const va = visibility(from);
    const vb = visibility(to);
    if (state.status[from] === "done" && state.status[to] === "done") return "done";
    if (va === "planned" || vb === "planned") return "frontier";
    if (va === "frontier" || vb === "frontier") return "frontier";
    if (state.status[from] === "live" || state.status[to] === "live") return "live";
    if (va === "revealed" && vb === "revealed") return "done";
    return "live";
  }

  function trailPath(a, b) {
    const dx = b.x - a.x;
    const cp = Math.max(3.5, dx * 0.42);
    return `M ${a.x} ${a.y} C ${a.x + cp} ${a.y}, ${b.x - cp} ${b.y}, ${b.x} ${b.y}`;
  }

  function trailThrough(nodes) {
    if (nodes.length < 2) return "";
    let d = `M ${nodes[0].x} ${nodes[0].y}`;
    for (let i = 1; i < nodes.length; i += 1) {
      const a = nodes[i - 1];
      const b = nodes[i];
      const dx = b.x - a.x;
      const cp = Math.max(3.5, dx * 0.42);
      d += ` C ${a.x + cp} ${a.y}, ${b.x - cp} ${b.y}, ${b.x} ${b.y}`;
    }
    return d;
  }

  function toast(msg) {
    const el = $(".toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove("show"), 1600);
  }

  function currentMission() {
    const selected = nodeById(state.current);
    const active = selected && state.status[selected.id] === "live"
      ? selected
      : DATA.nodes.find((n) => state.status[n.id] === "live");
    const latestDone = [...DATA.nodes]
      .filter((n) => state.status[n.id] === "done")
      .sort((a, b) => b.x - a.x || b.y - a.y)[0];

    const core = nodeById("target");
    const coreReady = core && (
      state.status[core.id] === "done" ||
      state.status[core.id] === "live" ||
      (state.status[core.id] === "pending" && preds(core.id).every((id) => state.status[id] === "done"))
    );
    const postCoreStarted = descendants("target").some(
      (id) => state.status[id] === "done" || state.status[id] === "live"
    );
    if (coreReady && !postCoreStarted) return core;

    if (active && (!latestDone || active.x >= latestDone.x)) return active;

    const nextReady = [...DATA.nodes]
      .filter((n) => {
        if (state.status[n.id] !== "pending") return false;
        return canActivate(n.id);
      })
      .sort((a, b) => b.x - a.x || b.y - a.y)[0];

    return nextReady || active || latestDone || DATA.nodes.find((n) => visibility(n.id) === "frontier") || DATA.nodes[DATA.nodes.length - 1];
  }

  function descriptionHTML(node) {
    const body = node.body[state.lang].trim();
    const points = state.lang === "zh"
      ? (body.match(/[^。！？]+[。！？]?/gu) || [body])
      : body.split(/(?<=[.!?])\s+(?=[A-Z])/u);
    const clean = points.map((point) => point.trim()).filter(Boolean);
    if (clean.length < 2) return `<p class="card-body">${body}</p>`;
    return `<ul class="detail-points">${clean.map((point) => `<li>${point}</li>`).join("")}</ul>`;
  }

  function storyOrder() {
    const destination = currentMission();
    if (!destination) return [];
    const visit = (id, seen = new Set()) => {
      if (id === destination.id) return [id];
      if (seen.has(id)) return null;
      seen.add(id);
      const lane = nodeById(id)?.lane;
      const outgoing = DATA.edges
        .filter(([from]) => from === id)
        .sort(([, a], [, b]) => Number(nodeById(b)?.lane === lane) - Number(nodeById(a)?.lane === lane));
      for (const [, to] of outgoing) {
        const branch = visit(to, new Set(seen));
        if (branch) return [id, ...branch];
      }
      return null;
    };
    return (visit("architecture") || [destination.id]).map(nodeById).filter(Boolean);
  }

  function cardHTML(id, withClose) {
    const n = nodeById(id);
    const st = state.status[id];
    const vis = visibility(id);
    const c = t();
    const badge =
      st === "done" ? c.crystallized : st === "live" ? c.live : vis === "frontier" ? c.frontier : c.legend.planned;
    const dependencies = preds(id).map(nodeById).filter(Boolean);
    const dependencyText = dependencies.length
      ? dependencies.map((item) => item.title[state.lang]).join(" · ")
      : c.noPrerequisites;
    const validation = n.validation && n.validation[state.lang];
    const forwardLocked = !canActivate(id);
    const backwardLocked = !canReset(id);
    const frozenPast = st === "done" && backwardLocked;
    const lockMessage = st === "pending" && forwardLocked ? c.blockedForward : "";
    return `
      ${withClose ? `<button class="card-close" data-close type="button" aria-label="${c.close}">×</button>` : ""}
      <div class="card-eyebrow">
        <span class="badge ${st === "done" ? "" : st}">${badge}</span>
        <span>${n.kicker[state.lang]}</span>
      </div>
      <h2>${n.title[state.lang]}</h2>
      <p class="summary">${n.summary[state.lang]}</p>
      ${descriptionHTML(n)}
      <div class="card-context">
        <div>
          <h3>${c.prerequisites}</h3>
          <p>${dependencyText}</p>
        </div>
        ${validation ? `<div class="validation-note"><h3>${c.validation}</h3><p>${validation}</p></div>` : ""}
      </div>
      ${frozenPast ? "" : `<div class="card-tools">
        <button class="ignite-only primary" data-act="done" type="button" ${forwardLocked || st === "done" ? "disabled" : ""}>${c.ignite}</button>
        <button class="ignite-only" data-act="live" type="button" ${forwardLocked || st === "live" ? "disabled" : ""}>${c.setLive}</button>
        ${st !== "pending" && !backwardLocked ? `<button class="ignite-only" data-act="pending" type="button">${c.extinguish}</button>` : ""}
      </div>`}
      ${lockMessage ? `<p class="stage-lock">${lockMessage}</p>` : ""}
    `;
  }

  function bindCard(el, id) {
    const close = el.querySelector("[data-close]");
    if (close) {
      close.addEventListener("click", (ev) => {
        ev.stopPropagation();
        hideMapCard();
      });
    }
    el.querySelectorAll("[data-act]").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        setStatus(id, btn.getAttribute("data-act"));
      });
    });
  }

  function renderDispatch() {
    const n = currentMission();
    const c = t();
    const el = $("[data-dispatch]");
    if (!n || !el) return;
    el.innerHTML = `
      <div class="k">${c.dispatch}</div>
      <h2>${n.title[state.lang]}</h2>
      <p>${n.summary[state.lang]}</p>
      <button type="button" data-goto>${c.goto}</button>
    `;
    el.querySelector("[data-goto]").addEventListener("click", () => {
      $("[data-voyage]").scrollIntoView({ behavior: "smooth", block: "center" });
      showMapCard(n.id);
    });
  }

  function showMapCard(id) {
    const card = $("[data-map-card]");
    const node = document.querySelector(`.station[data-id="${id}"]`);
    const item = nodeById(id);
    if (!node || visibility(id) === "hidden") return;
    state.selected = id;
    card.hidden = false;
    card.dataset.side = item.x > 60 ? "left" : "right";
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-label", item.title[state.lang]);
    card.innerHTML = cardHTML(id, true);
    bindCard(card, id);
    document.querySelectorAll(".station").forEach((el) => {
      const pinned = el.getAttribute("data-id") === id;
      el.classList.toggle("pinned", pinned);
      el.querySelector("button")?.setAttribute("aria-expanded", String(pinned));
    });
  }

  function hideMapCard() {
    const card = $("[data-map-card]");
    card.hidden = true;
    document.querySelectorAll(".station.pinned").forEach((el) => {
      el.classList.remove("pinned");
      el.querySelector("button")?.setAttribute("aria-expanded", "false");
    });
    state.selected = null;
  }

  function replay() {
    if (state.playing) return;
    const stops = storyOrder();
    if (!stops.length) return;
    const token = $("[data-traveler]");
    const map = $("[data-voyage]");
    map.classList.add("playing");
    state.playing = true;
    hideMapCard();
    map.scrollIntoView({ behavior: reducedMotion.matches ? "auto" : "smooth", block: "center" });
    let i = 0;
    const step = () => {
      document.querySelectorAll(".station.passed").forEach((el) => el.classList.remove("passed"));
      if (i >= stops.length) {
        state.playing = false;
        map.classList.remove("playing");
        const last = stops[stops.length - 1];
        showMapCard(last.id);
        return;
      }
      const n = stops[i];
      token.style.left = n.x + "%";
      token.style.top = n.y + "%";
      const el = document.querySelector(`.station[data-id="${n.id}"]`);
      if (el) el.classList.add("passed");
      i += 1;
      setTimeout(step, reducedMotion.matches ? 0 : 420);
    };
    const first = stops[0];
    token.style.left = first.x + "%";
    token.style.top = first.y + "%";
    setTimeout(step, reducedMotion.matches ? 0 : 80);
  }

  function setLang(lang) {
    state.lang = lang;
    localStorage.setItem(LANG_STORAGE_KEY, lang);
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    render();
    if (state.selected) showMapCard(state.selected);
  }

  function renderCopy() {
    const c = t();
    $("[data-copy=brand]").textContent = c.brand;
    $("[data-copy=lattice]").textContent = c.lattice;
    $("[data-copy=curatorBanner]").textContent = c.curatorBanner;
    $("[data-copy=lang]").textContent = c.lang;
    $("[data-copy=curate]").textContent = state.curating ? c.curating : t().curate;
    $("[data-copy=export]").textContent = c.export;
    $("[data-copy=reset]").textContent = c.reset;
    $("[data-copy=draw]").textContent = c.draw;
    $("[data-copy=drawHint]").textContent = c.drawHint;
    const articleLink = $("[data-design-article]");
    articleLink.href = DATA.featuredArticle.href;
    articleLink.setAttribute("aria-label", c.articleLabel);
    articleLink.title = c.articleLabel;
    $("[data-replay]").setAttribute(
      "aria-label",
      `${c.draw}${state.lang === "zh" ? "：" : ": "}${c.drawHint}`
    );
    document.querySelectorAll("[data-copy=laneAccount]").forEach((el) => (el.textContent = c.lanes.account));
    document.querySelectorAll("[data-copy=laneSoftware]").forEach((el) => (el.textContent = c.lanes.software));
    document.querySelectorAll("[data-copy=laneConsensus]").forEach((el) => (el.textContent = c.lanes.consensus));
    document.querySelectorAll("[data-copy=allTracks]").forEach((el) => (el.textContent = c.allTracks));
    $("[data-copy=legendDone]").textContent = c.legend.done;
    $("[data-copy=legendLive]").textContent = c.legend.live;
    $("[data-copy=legendPlanned]").textContent = c.legend.planned;
    renderStats();
    renderDispatch();
  }

  function renderStats() {
    const c = t();
    const n = counts();
    const pct = Math.round((n.done / n.total) * 100);
    $("[data-stat=done]").textContent = String(n.done).padStart(2, "0");
    $("[data-stat=live]").textContent = String(n.live).padStart(2, "0");
    $("[data-stat=pending]").textContent = String(n.pending).padStart(2, "0");
    $("[data-copy=statDone]").textContent = c.stats.ignited;
    $("[data-copy=statLive]").textContent = c.stats.live;
    $("[data-copy=statPending]").textContent = c.stats.remaining;
    $("[data-pct]").textContent = `${pct}%`;
    $("[data-chip]").textContent = `${n.done}/${n.total}`;
  }

  function renderTrail() {
    const svg = $("[data-trail]");
    const routes = DATA.edges
      .map(([from, to]) => {
        const a = nodeById(from);
        const b = nodeById(to);
        const kind = edgeKind(from, to);
        if (kind === "hidden") return "";
        const d = trailPath(a, b);
        const track = b.kind === "horizon" ? a.lane : b.lane;
        return `
          <g class="route ${kind} ${track}" data-from="${from}" data-to="${to}">
            <path class="tube" d="${d}" pathLength="100" />
            <path class="core" d="${d}" pathLength="100" />
          </g>`;
      })
      .join("");
    const mission = currentMission();
    const current = mission
      ? ancestorEdges(mission.id)
          .map(([from, to]) => {
            const d = trailPath(nodeById(from), nodeById(to));
            return `<g class="network-current" aria-hidden="true">
              <path class="current-halo" d="${d}" pathLength="100" />
              <path class="current-pulse" d="${d}" pathLength="100" />
            </g>`;
          })
          .join("")
      : "";
    svg.innerHTML = routes + current;
    const map = $("[data-voyage]");
    if (!state.unfurled) {
      map.classList.add("unfurl");
      state.unfurled = true;
      setTimeout(() => map.classList.remove("unfurl"), 1500);
    }
  }

  function renderStations() {
    const root = $("[data-stations]");
    const current = currentMission();
    const visualOrder = [...DATA.nodes].sort((a, b) => a.x - b.x || a.y - b.y);
    root.innerHTML = visualOrder
      .map((n) => {
        const st = state.status[n.id];
        const vis = visibility(n.id);
        const locked = st === "pending" && !canActivate(n.id);
        const frontierLabel = n.kind === "horizon" ? t().destination : t().frontier;
        const isCurrent = current && current.id === n.id;
        const now = isCurrent ? `<span class="now-tag">NOW</span>` : vis === "frontier" ? `<span class="now-tag">${frontierLabel}</span>` : "";
        const label = n.title[state.lang];
        return `
          <div class="station ${st} ${n.kind} ${n.lane} ${vis} ${locked ? "locked" : ""} ${isCurrent ? "current" : ""}" data-id="${n.id}" data-stage="${stageNumber(n)}" style="left:${n.x}%; top:${n.y}%">
            <button class="gadget" type="button" ${vis === "hidden" ? "tabindex='-1'" : ""} aria-label="${n.title[state.lang]}" aria-controls="waypoint-detail" aria-expanded="false" ${st === "live" ? "aria-current='step'" : ""}>
              ${now}
              <span class="orb"></span>
              <span class="name">${label}</span>
            </button>
          </div>`;
      })
      .join("");
    root.querySelectorAll(".station").forEach((el) => {
      el.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const id = el.getAttribute("data-id");
        showMapCard(id);
      });
    });
    scheduleLabelLayout();
  }

  function scheduleLabelLayout() {
    cancelAnimationFrame(labelLayoutFrame);
    labelLayoutFrame = requestAnimationFrame(layoutStationLabels);
  }

  function layoutStationLabels() {
    const map = $("[data-voyage]");
    if (!map) return;
    const mapRect = map.getBoundingClientRect();
    const stations = [...document.querySelectorAll(".station")];

    if (mapRect.width <= 980) {
      stations.forEach((station) => {
        station.style.removeProperty("--label-width");
        station.style.removeProperty("--label-nudge");
      });
      return;
    }

    const byLane = new Map();
    for (const station of stations) {
      const node = nodeById(station.dataset.id);
      if (!node) continue;
      if (!byLane.has(node.lane)) byLane.set(node.lane, []);
      byLane.get(node.lane).push({ node, station, label: station.querySelector(".name") });
    }

    for (const [lane, entries] of byLane) {
      entries.sort((a, b) => a.node.x - b.node.x);

      entries.forEach((entry, index) => {
        const previous = entries
          .slice(0, index)
          .reverse()
          .find((candidate) => Math.abs(candidate.node.y - entry.node.y) < 9)?.node;
        const next = entries
          .slice(index + 1)
          .find((candidate) => Math.abs(candidate.node.y - entry.node.y) < 9)?.node;
        const leftGap = previous ? ((entry.node.x - previous.x) / 100) * mapRect.width : Infinity;
        const rightGap = next ? ((next.x - entry.node.x) / 100) * mapRect.width : Infinity;
        const neighbourGap = Math.min(leftGap, rightGap);
        const edgeSpace = (Math.min(entry.node.x, 100 - entry.node.x) / 100) * mapRect.width * 2 - 28;
        const neighbourSpace = Number.isFinite(neighbourGap) ? neighbourGap * 0.78 : 224;
        const width = Math.max(88, Math.min(224, edgeSpace, neighbourSpace));
        entry.station.style.setProperty("--label-width", `${Math.floor(width)}px`);
        entry.station.style.setProperty("--label-nudge", "0px");
      });

      const placed = [];
      for (const entry of entries) {
        if (!entry.label) continue;
        const direction = lane === "account" ? -1 : 1;
        let nudge = 0;
        let rect = entry.label.getBoundingClientRect();
        for (let attempt = 0; attempt < 4; attempt += 1) {
          const collision = placed.some(
            (other) =>
              rect.left < other.right + 8 &&
              rect.right > other.left - 8 &&
              rect.top < other.bottom + 6 &&
              rect.bottom > other.top - 6
          );
          if (!collision) break;
          nudge += direction * 20;
          entry.station.style.setProperty("--label-nudge", `${nudge}px`);
          rect = entry.label.getBoundingClientRect();
        }
        placed.push(rect);
      }
    }
  }

  function setStatus(id, next) {
    if (!allowedStatuses.has(next)) return;
    const c = t();
    if (next === "live" && state.status[id] === "done" && !canReset(id)) return;
    if ((next === "live" || next === "done") && !canActivate(id)) {
      toast(c.blockedForward);
      return;
    }
    if (next === "pending" && !canReset(id)) {
      return;
    }
    const before = {};
    for (const n of DATA.nodes) before[n.id] = visibility(n.id);
    state.status[id] = next;
    if (next === "live") state.current = id;
    else if (state.current === id) state.current = null;
    saveStatus();
    toast(next === "done" ? c.igniteToast : next === "live" ? c.liveToast : c.dormantToast);
    render();
    for (const n of DATA.nodes) {
      if (before[n.id] !== "frontier" && visibility(n.id) === "frontier") {
        const el = document.querySelector(`.station[data-id="${n.id}"]`);
        if (el) el.classList.add("awaken");
      }
    }
    renderDispatch();
    showMapCard(id);
  }

  function toggleCurate() {
    state.curating = !state.curating;
    document.body.classList.toggle("curating", state.curating);
    $("[data-copy=curate]").textContent = state.curating ? t().curating : t().curate;
    $("[data-copy=curate]").classList.toggle("active", state.curating);
    if (state.selected) showMapCard(state.selected);
  }

  function exportProgress() {
    const blob = new Blob([JSON.stringify(state.status, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "progress.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function resetProgress() {
    localStorage.removeItem(DATA.storageKey);
    localStorage.removeItem(`${DATA.storageKey}.current`);
    state.status = defaultStatus();
    state.current = null;
    render();
    hideMapCard();
    state.selected = null;
    overlayRemoteProgress();
  }

  function render() {
    renderCopy();
    renderTrail();
    renderStations();
  }

  function bind() {
    $("[data-copy=lang]").addEventListener("click", () =>
      setLang(state.lang === "zh" ? "en" : "zh")
    );
    $("[data-copy=curate]").addEventListener("click", toggleCurate);
    $("[data-copy=export]").addEventListener("click", exportProgress);
    $("[data-copy=reset]").addEventListener("click", resetProgress);
    $("[data-replay]").addEventListener("click", (ev) => {
      ev.stopPropagation();
      replay();
    });
    document.querySelectorAll(".map-bar [data-focus]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const focus = btn.getAttribute("data-focus");
        $("[data-voyage]").dataset.focus = focus;
        document.querySelectorAll(".map-bar [data-focus]").forEach((b) => {
          const selected = b === btn;
          b.classList.toggle("on", selected);
          b.setAttribute("aria-pressed", String(selected));
        });
      });
    });
    $("[data-voyage]").addEventListener("pointermove", (ev) => {
      if (reducedMotion.matches) return;
      const r = ev.currentTarget.getBoundingClientRect();
      const x = ((ev.clientX - r.left) / r.width - 0.5) * 4;
      const y = ((ev.clientY - r.top) / r.height - 0.5) * 3;
      ev.currentTarget.style.setProperty("--mx", x.toFixed(1) + "px");
      ev.currentTarget.style.setProperty("--my", y.toFixed(1) + "px");
    });
    $("[data-voyage]").addEventListener("pointerleave", (ev) => {
      ev.currentTarget.style.setProperty("--mx", "0px");
      ev.currentTarget.style.setProperty("--my", "0px");
    });
    $("[data-voyage]").addEventListener("click", (ev) => {
      if (!ev.target.closest(".station") && !ev.target.closest("[data-map-card]")) hideMapCard();
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") hideMapCard();
      if ((ev.key === "e" || ev.key === "E") && !ev.metaKey && !ev.ctrlKey) {
        if (document.activeElement !== document.body) return;
        toggleCurate();
      }
    });
    const map = $("[data-voyage]");
    if ("ResizeObserver" in window && map) {
      labelResizeObserver = new ResizeObserver(scheduleLabelLayout);
      labelResizeObserver.observe(map);
    } else {
      window.addEventListener("resize", scheduleLabelLayout, { passive: true });
    }
    if (document.fonts?.ready) document.fonts.ready.then(scheduleLabelLayout);
  }

  loadStatus();
  bind();
  render();
  overlayRemoteProgress();
})();
