"use strict";
const $ = (id) => document.getElementById(id);
// Normalize timestamp labels only. Saved evidence and link targets stay exact.
const centralTime = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/Chicago", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  timeZoneName: "short",
});
function centralLabel(original, day, clock) {
  const instant = new Date(day + "T" + clock + "Z");
  if (Number.isNaN(instant.getTime())) return original;
  const p = Object.fromEntries(centralTime.formatToParts(instant).map(x => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second} ${p.timeZoneName} (${clock}Z)`;
}
function readableTime(value) {
  return String(value)
    .replace(/\b(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(?:[.-]\d+)?(?:Z|\+0000)\b/g,
      "$1-$2-$3 $4:$5:$6Z")
    .replace(/\b(\d{4}-\d{2}-\d{2})T(\d{2})(\d{2})(\d{2})(?:-\d+)?\+0000\b/g,
      "$1 $2:$3:$4Z")
    .replace(/\b(\d{4}-\d{2}-\d{2})_(\d{2})-(\d{2})-(\d{2})Z\b/g,
      "$1 $2:$3:$4Z")
    .replace(/\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)\b/g,
      centralLabel);
}
function timestampMillis(value) {
  return Date.parse(String(value).replace(/^(\d{4}-\d{2}-\d{2}) /, "$1T"));
}
function orderedCases() {
  return [...state.cases].sort((a, b) => timestampMillis(b.created_at) - timestampMillis(a.created_at));
}
let state,
  selected = new URLSearchParams(location.search).get("case") || null,
  selectedVersion = null,
  shownReport = "",
  shownActivity = "",
  shownMessages = "",
  shownImages = "",
  approvalKey = "",
  artifact = null;
const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
function error(e) {
  $("error").textContent = e.message || String(e);
  $("error").hidden = false;
}
async function api(path, data) {
  const r = await fetch("/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers: data === undefined ? {} : { "Content-Type": "application/json" },
    body: data === undefined ? undefined : JSON.stringify(data),
    credentials: "same-origin",
  });
  const d = await r.json();
  if (!r.ok) throw Error(d.error || "Request failed");
  return d;
}
function act(fn) {
  return async (e) => {
    if (e) e.preventDefault();
    try {
      $("error").hidden = true;
      await fn();
    } catch (e) {
      error(e);
    }
  };
}
function choose(id) {
  selected = id;
  selectedVersion = null;
  shownReport = "";
  shownActivity = "";
  shownMessages = "";
  shownImages = "";
  approvalKey = null;
  artifact = null;
  $("reportView").replaceChildren();
  $("toc").replaceChildren();
  $("artifacts").replaceChildren();
  $("artifactMeta").textContent = "";
  $("artifactView").textContent = "";
  $("more").hidden = true;
  $("coverageView").replaceChildren();
  render();
  loadArtifacts().catch(error);
}
function caseNow() {
  return state.cases.find((c) => c.id === selected);
}
async function job(kind, text = "") {
  if (!selected) throw Error("Select a case");
  await api("jobs", {
    case_id: selected,
    kind,
    text,
    request_id: crypto.randomUUID(),
  });
  await refresh();
}
function setTab(name) {
  document.querySelectorAll(".tab").forEach((n) => (n.hidden = n.id !== name));
  document
    .querySelectorAll("[data-tab]")
    .forEach((n) => n.classList.toggle("selected", n.dataset.tab === name));
  if (name === "evidence") loadArtifacts().catch(error);
  if (name === "coverage") loadCoverage().catch(error);
}
function inline(node, text, base) {
  const re = /\[([^\]]+)\]\(([^)]+)\)/g;
  let start = 0,
    m;
  while ((m = re.exec(text))) {
    node.append(document.createTextNode(text.slice(start, m.index)));
    const value = m[2];
    if (value.startsWith("#")) {
      const a = el("a", m[1]);
      a.href = value;
      node.append(a);
    } else if (
      !/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(value) &&
      !value.startsWith("/") &&
      !value.includes("\\") &&
      !value.split("/").includes("..")
    ) {
      const a = el("a", m[1]);
      a.href = "#evidence";
      a.onclick = act(async () => {
        const citation = new URLSearchParams(value.split("#")[1] || "").get("citation");
        if (citation && base.startsWith("reports/")) {
          const match = /^(.*):(\d+)$/.exec(citation);
          if (!match) throw Error("Invalid citation link");
          const resolved = await api("citations?case=" + encodeURIComponent(selected) +
            "&report=" + encodeURIComponent(base.slice(8)) + "&finding=" + encodeURIComponent(match[1]) + "&index=" + match[2]);
          if (resolved.artifact_path !== base + "/" + value.split("#")[0]) throw Error("Citation link targets a different artifact");
          await viewArtifact(resolved.artifact_path);
          $("artifactView").textContent = JSON.stringify(resolved, null, 2) + "\n\nRaw artifact preview:\n" + $("artifactView").textContent;
        } else {
          await viewArtifact(base + "/" + value.split("#")[0]);
        }
        setTab("evidence");
      });
      node.append(a);
    } else {
      node.append(document.createTextNode(m[1] + " [" + value + "]"));
    }
    start = re.lastIndex;
  }
  node.append(document.createTextNode(text.slice(start)));
}
function enlargeCoin(img) {
  let dialog = $("coinZoom");
  if (!dialog) {
    dialog = el("dialog");
    dialog.id = "coinZoom";
    dialog.setAttribute("aria-label", "Enlarged coin. Click anywhere or press Escape to close.");
    dialog.onclick = (event) => { if (event.button === 0) dialog.close(); };
    document.body.append(dialog);
  }
  const large = el("img");
  large.src = img.src;
  large.alt = img.alt;
  dialog.replaceChildren(large, el("p", "Click anywhere to close · Right-click the coin to save image"));
  dialog.showModal();
}
function coinImage(path, label) {
  const img = el("img", undefined, "challenge-coin");
  img.src = "/api/coin?case=" + selected + "&path=" + encodeURIComponent(path);
  img.alt = label + " — decorative image identity, not forensic evidence";
  img.title = img.alt;
  img.onerror = () => img.remove();
  img.tabIndex = 0;
  img.setAttribute("role", "button");
  img.setAttribute("aria-label", "Enlarge " + label + " coin");
  img.onclick = () => enlargeCoin(img);
  img.onkeydown = (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      enlargeCoin(img);
    }
  };
  return img;
}
function renderMarkdown(text, base) {
  const article = $("reportView"),
    toc = $("toc");
  article.replaceChildren();
  toc.replaceChildren();
  if (!text.includes("![Decorative coin for ")) {
    const gallery = el("div", undefined, "coin-gallery");
    for (const coin of caseNow()?.coins || []) {
      if (coin.path) gallery.append(coinImage(coin.path, coin.label));
    }
    article.append(gallery);
  }
  let code = null,
    count = 0;
  for (const line of text.split("\n")) {
    const coin = /^!\[(Decorative coin for [^\]]+)\]\((assets\/coins\/[a-f0-9]{64}\.(?:png|svg))\)$/.exec(line);
    if (!code && coin) {
      article.append(coinImage(base + "/" + coin[2], coin[1]));
      continue;
    }
    if (line.startsWith("```")) {
      if (code) {
        article.append(code);
        code = null;
      } else code = el("pre", "");
      continue;
    }
    if (code) {
      code.textContent += line + "\n";
      continue;
    }
    const h = /^(#{1,6})\s+(.*)/.exec(line);
    if (h) {
      const n = el("h" + Math.min(h[1].length, 4), h[2]);
      n.id = "section-" + ++count;
      article.append(n);
      if (h[1].length <= 2) {
        const a = el("a", h[2]);
        a.href = "#" + n.id;
        toc.append(a);
      }
    } else if (line.trim()) {
      const n = el("p");
      inline(n, line, base);
      article.append(n);
    }
  }
  if (code) article.append(code);
}
async function showReport(version) {
  if (!version) {
    shownReport = "";
    $("reportView").replaceChildren(el("p", "No report yet. Run readiness, then Generate report."));
    $("toc").replaceChildren();
    return;
  }
  const key = selected + "/" + version.id + "/" + version.status;
  if (shownReport === key) return;
  shownReport = key;
  try {
    const path = "reports/" + version.id + "/report.md";
    const data = await api(
      "file?case=" + selected + "&path=" + encodeURIComponent(path),
    );
    if (shownReport !== key) return;
    renderMarkdown(data.text, "reports/" + version.id);
    const citationCase = selected;
    const checks = el("button", "Inspect evidence citations");
    const panel = el("div");
    checks.onclick = act(async () => {
      panel.replaceChildren();
      async function page(offset = 0) {
        const base = "citations?case=" + encodeURIComponent(citationCase) + "&report=" + encodeURIComponent(version.id);
        const data = await api(base + "&offset=" + offset);
        for (const ref of data.entries) {
          const b = el("button", ref.finding + " · " + ref.artifact_id + " · " + ref.validation);
          b.onclick = act(async () => {
            const resolved = await api(base + "&finding=" + encodeURIComponent(ref.finding) + "&index=" + ref.index);
            const value = el("pre", JSON.stringify(resolved, null, 2));
            const raw = el("button", "Open supporting artifact");
            raw.onclick = act(async () => { await viewArtifact(resolved.artifact_path); setTab("evidence"); });
            panel.replaceChildren(value, raw);
          });
          panel.append(b);
        }
        if (data.next_offset !== null) {
          const more = el("button", "More citations");
          more.onclick = act(async () => { more.remove(); await page(data.next_offset); });
          panel.append(more);
        }
        if (!data.entries.length) panel.append(el("p", "No finding citations in this report."));
      }
      await page();
    });
    $("reportView").append(checks, panel);
    if (data.truncated) {
      const b = el(
        "button",
        "Report preview truncated — read remaining chunks",
      );
      b.onclick = act(() => viewArtifact(path));
      $("reportView").append(b);
    }
  } catch (e) {
    if (shownReport !== key) return;
    renderMarkdown("Report is not available yet: " + e.message, "reports/" + version.id);
    $("toc").replaceChildren();
  }
}
function render() {
  if (!state) return;
  $("connection").textContent = state.account.connected
    ? "Codex · " + state.account.type
    : "Local UI connected · Codex checked on readiness";
  $("root").textContent = "Evidence root: " + state.evidence_root;
  $("pick").disabled = !state.native_picker;
  const cases = $("cases");
  cases.replaceChildren();
  for (const c of orderedCases()) {
    const b = el(
      "button",
      c.title,
      "case-button" + (c.id === selected ? " selected" : ""),
    );
    b.onclick = () => choose(c.id);
    cases.append(b);
  }
  const c = caseNow();
  $("empty").hidden = !!c;
  $("case").hidden = !c;
  if (c) {
    $("caseTitle").textContent = c.title;
    $("ready").textContent = c.readiness.status;
    const imageKey = JSON.stringify([c.id, c.images, c.coins]);
    if (shownImages !== imageKey) {
    $("images").replaceChildren(
      ...c.images.map((i) =>
        el(
          "div",
          i.id +
            " · " +
            i.path +
            "\n" +
            i.size_bytes.toLocaleString() +
            " bytes · SHA-256 " +
            (i.sha256 || "pending"),
          "image",
        ),
      ),
    );
    for (const [index, image] of c.images.entries()) {
      const coin = (c.coins || []).find(x => x.image_id === image.id && x.path);
      if (coin) $("images").children[index].prepend(coinImage(coin.path, coin.label));
    }
    shownImages = imageKey;
    }
    $("reasons").replaceChildren(
      ...c.readiness.reasons.map((r) => el("p", r, "subtle")),
    );
    const ready = ["Ready", "Ready with limitations"].includes(
      c.readiness.status,
    );
    $("report").disabled = !ready;
    $("update").disabled =
      !ready || !c.reports.some((r) => r.status === "sealed");
    const running = state.jobs.find(
      (j) => j.case_id === c.id && ["running", "stopping"].includes(j.status),
    );
    $("operation").textContent = running
      ? readableTime(running.progress || running.kind) +
        " · " +
        Math.floor((Date.now() - timestampMillis(running.started_at)) / 1000) +
        "s elapsed" +
        (running.status === "stopping" ? " · stopping…" : "")
      : "";
    const versions = $("versions");
    versions.replaceChildren();
    for (const r of [...c.reports].reverse()) {
      const b = el("button", readableTime(r.created_at) + " · " + r.status);
      b.onclick = () => {
        selectedVersion = r.id;
        shownReport = "";
        showReport(r);
      };
      versions.append(b);
    }
    const v =
      c.reports.find((r) => r.id === selectedVersion) || c.reports.at(-1);
    showReport(v);
    const mkey = JSON.stringify(c.messages);
    if (shownMessages !== mkey) {
      $("messages").replaceChildren(
        ...c.messages.map((m) =>
          el(
            "div",
            m.role.toUpperCase() + " · " + readableTime(m.time) + "\n" + m.text,
            "message " + m.role,
          ),
        ),
      );
      shownMessages = mkey;
    }
    const akey = JSON.stringify(c.activity);
    if (shownActivity !== akey) {
      $("activityList").replaceChildren(
        ...[...c.activity].reverse().map((a) => {
          const d = el("details", undefined, "event");
          d.append(
            el("summary", readableTime(a.time) + " · " + a.kind),
            el("pre", readableTime(JSON.stringify(a.detail, null, 2))),
          );
          return d;
        }),
      );
      shownActivity = akey;
    }
    renderApprovals(c);
  }
  $("queue").replaceChildren(
    ...state.jobs
      .slice(-30)
      .reverse()
      .map((j) => {
        const title =
          state.cases.find((c) => c.id === j.case_id)?.title || j.case_id;
        return el(
          "p",
          title +
            " · " +
            j.kind +
            " · " +
            j.status +
            (j.error ? " — " + j.error : ""),
        );
      }),
  );
}
function renderApprovals(c) {
  const list = state.approvals.filter((a) => a.case_id === c.id),
    key = list.map((a) => a.id).join();
  if (key === approvalKey) return;
  approvalKey = key;
  $("approvals").replaceChildren();
  for (const a of list) {
    const d = el("div", undefined, "approval");
    d.append(
      el("h3", "Your decision is required"),
      el("pre", JSON.stringify(a.params, null, 2)),
    );
    if (a.method === "mcpServer/elicitation/request") {
      const inputs = {};
      let supported = true;
      for (const [key, field] of Object.entries(
        a.params.requestedSchema.properties || {},
      )) {
        const label = el("label", field.title || key);
        const choices = field.enum || field.oneOf?.map((x) => x.const);
        let input;
        if (choices) {
          input = el("select");
          const blank = el("option", "Choose an answer");
          blank.value = "";
          input.append(blank);
          for (const value of choices) {
            const option = el("option", value);
            option.value = value;
            input.append(option);
          }
        } else if (
          ["string", "boolean", "integer", "number"].includes(field.type)
        ) {
          input = el("input");
          input.type =
            field.type === "boolean"
              ? "checkbox"
              : ["integer", "number"].includes(field.type)
                ? "number"
                : "text";
        } else {
          supported = false;
          label.append(
            el(
              "p",
              "Unsupported form field; decline this request and inspect its details.",
            ),
          );
          d.append(label);
          continue;
        }
        input.dataset.field = key;
        label.append(input);
        d.append(label);
        inputs[key] = { input, field };
      }
      for (const [text, action] of [
        ["Approve / submit once", "accept"],
        ["Decline", "decline"],
        ["Cancel", "cancel"],
      ]) {
        const button = el("button", text);
        button.disabled = action === "accept" && !supported;
        button.onclick = act(async () => {
          const content = {};
          if (action === "accept")
            for (const [key, { input, field }] of Object.entries(inputs)) {
              if (field.type === "boolean") content[key] = input.checked;
              else if (["integer", "number"].includes(field.type))
                content[key] = Number(input.value);
              else if (input.value !== "") content[key] = input.value;
            }
          await api("approval", { id: a.id, answer: { action, content } });
        });
        d.append(button);
      }
    } else if (a.method === "item/tool/requestUserInput") {
      const inputs = {};
      for (const q of a.params.questions || []) {
        const label = el("label", q.question);
        const input = el("input");
        label.append(input);
        d.append(label);
        inputs[q.id] = input;
      }
      const b = el("button", "Submit answer");
      b.onclick = act(async () => {
        const answer = {};
        for (const [id, input] of Object.entries(inputs))
          answer[id] = { answers: [input.value] };
        await api("approval", { id: a.id, answer });
      });
      d.append(b);
    } else {
      for (const [text, answer] of [
        ["Approve once", "accept"],
        ["Decline", "decline"],
        ["Cancel turn", "cancel"],
      ]) {
        const b = el("button", text);
        b.onclick = act(() => api("approval", { id: a.id, answer }));
        d.append(b);
      }
    }
    $("approvals").append(d);
  }
}
async function loadArtifacts() {
  if (!selected) return;
  const caseId = selected;
  const data = await api("artifacts?case=" + caseId);
  if (selected !== caseId) return;
  $("artifacts").replaceChildren(
    ...data.files.map((f) => {
      const b = el(
        "button",
        readableTime(f.path) + " · " + f.size_bytes.toLocaleString() + " bytes",
      );
      b.onclick = act(() => viewArtifact(f.path));
      b.title = f.path;
      return b;
    }),
  );
  if (data.truncated)
    $("artifacts").append(
      el("p", "First 5,000 files shown. Complete artifacts remain on disk."),
    );
}
async function viewArtifact(path, offset = 0) {
  const caseId = selected;
  const data = await api(
    "file?case=" +
      caseId +
      "&path=" +
      encodeURIComponent(path) +
      "&offset=" +
      offset,
  );
  if (selected !== caseId) return;
  artifact = { path, offset: data.next_offset };
  $("artifactMeta").textContent =
    readableTime(path) +
    " · bytes " +
    offset +
    "–" +
    data.next_offset +
    " of " +
    data.size +
    (data.truncated ? " · truncated; continue below" : "");
  $("artifactMeta").title = path;
  let text = data.text;
  if (offset === 0 && !data.truncated && path.endsWith(".json")) {
    try {
      text = JSON.stringify(JSON.parse(text), null, 2);
    } catch {}
  }
  if (offset === 0 && !data.truncated && path.endsWith(".jsonl")) {
    try {
      text = text
        .trim()
        .split("\n")
        .map(
          (l, i) =>
            "Record " + (i + 1) + "\n" + JSON.stringify(JSON.parse(l), null, 2),
        )
        .join("\n\n");
    } catch {}
  }
  $("artifactView").textContent = text;
  $("more").hidden = !data.truncated;
  setTab("evidence");
}
async function loadCoverage() {
  const c = caseNow();
  if (!c) return;
  const panel = $("coverageView");
  panel.replaceChildren(el("p", "Reading saved manifests and outputs; no analysis is started."));
  const sections = [];
  for (const image of c.images) {
    const section = el("section");
    section.append(el("h3", image.id));
    const base = "coverage?case=" + encodeURIComponent(c.id) + "&image=" + encodeURIComponent(image.id);
    async function page(offset = 0) {
      const data = await api(base + "&offset=" + offset);
      if (!offset) {
        section.append(el("p", "Scope: " + data.scope + ". " +
          data.summary.entries_with_successful_collection + " / " + data.summary.declared_plan_entries +
          " declared entries have successful collection. Questions answered: not determined."));
        section.append(el("p", data.summary.saved_attempts + " saved attempts; " +
          data.summary.physical_commands_recorded + " physical commands with recorded exit metadata; " +
          data.summary.reuse_requests + " reuse requests."));
        for (const text of data.limitations) section.append(el("p", text, "subtle"));
        if (data.issues.length) section.append(el("pre", JSON.stringify(data.issues, null, 2)));
        const jobs = el("details");jobs.append(el("summary", "Orchestration jobs (not plugin completion)"),
          el("pre", readableTime(JSON.stringify({jobs:data.orchestration_jobs, request_failures:data.request_failures}, null, 2))));section.append(jobs);
      }
      for (const entry of data.entries) {
        const detail = el("details");
        detail.append(el("summary", (entry.question || entry.plugin) + " · " + entry.effective.execution +
          " · " + entry.effective.applicability + " · " + entry.effective.availability));
        detail.append(el("pre", JSON.stringify({plugin:entry.plugin, arguments:entry.arguments,
          question_answered:entry.question_answered, effective:entry.effective}, null, 2)));
        async function attempts(batch) {
          for (const a of batch.attempts) {
            detail.append(el("pre", readableTime(JSON.stringify(a, null, 2))));
            const manifest = el("button", "Open attempt " + a.run_id);
            manifest.onclick = act(async () => { await viewArtifact("analysis/" + a.manifest); setTab("evidence"); });
            detail.append(manifest);
            for (const e of a.evidence) {
              const evidence = el("button", "Open saved evidence");
              evidence.onclick = act(async () => { await viewArtifact("analysis/" + e.path); setTab("evidence"); });
              detail.append(evidence);
            }
          }
          if (batch.attempt_next_offset !== null) {
            const more = el("button", "More attempts");
            more.onclick = act(async () => {
              const next = await api(base + "&entry=" + encodeURIComponent(entry.entry_id) + "&attempt_offset=" + batch.attempt_next_offset);
              more.remove(); await attempts(next.entries[0]);
            });detail.append(more);
          }
        }
        await attempts(entry);section.append(detail);
      }
      if (data.delivery.next_offset !== null) {
        const more = el("button", "More coverage scopes");
        more.onclick = act(async () => {more.remove(); await page(data.delivery.next_offset);});section.append(more);
      }
    }
    await page();sections.push(section);
  }
  if (selected === c.id) panel.replaceChildren(...sections);
}
$("loadCoverage").onclick = act(loadCoverage);

async function browse(path = "") {
  const data = await api("browse?path=" + encodeURIComponent(path));
  const nodes = [];
  if (path) {
    const b = el("button", "↑ Parent folder");
    b.onclick = act(() => browse(path.split("/").slice(0, -1).join("/")));
    nodes.push(b);
  }
  for (const f of data.entries) {
    const b = el("button", (f.directory ? "▸ " : "+ ") + f.name);
    b.onclick = act(async () => {
      if (f.directory) return browse(f.relative);
      const paths = $("paths").value.split("\n").filter(Boolean);
      if (!paths.includes(f.path)) paths.push(f.path);
      $("paths").value = paths.join("\n");
    });
    nodes.push(b);
  }
  $("files").replaceChildren(...nodes);
}
async function refresh() {
  state = await api("state");
  if (!caseNow()) choose(orderedCases()[0]?.id || null);
  else render();
}
$("add").onclick = act(async () => {
  const r = await api("cases", {
    paths: $("paths")
      .value.split("\n")
      .map((p) => p.trim())
      .filter(Boolean),
    related: $("related").checked,
    title: $("title").value,
    source: $("source").value,
  });
  $("paths").value = "";
  await refresh();
  choose(r.cases[0].id);
});
$("browse").onclick = act(() => browse());
$("pick").onclick = act(async () => {
  const r = await api("pick", {});
  $("paths").value = r.paths.join("\n");
});
$("readiness").onclick = act(() => job("readiness"));
$("report").onclick = act(() => job("report", $("focus").value));
$("update").onclick = act(() => job("update", $("focus").value));
$("stop").onclick = act(async () => {
  await api("stop", {});
  await refresh();
});
$("questionForm").onsubmit = act(async () => {
  await job("question", $("question").value);
  $("question").value = "";
});
$("more").onclick = act(() => viewArtifact(artifact.path, artifact.offset));
document
  .querySelectorAll("[data-tab]")
  .forEach((b) => (b.onclick = () => setTab(b.dataset.tab)));
(async () => {
  try {
    const token = location.hash.slice(1);
    if (token) {
      history.replaceState(null, "", location.pathname + location.search);
      await api("unlock", { token });
    }
    await refresh();
    setInterval(() => refresh().catch(error), 1500);
  } catch (e) {
    error(e);
  }
})();
