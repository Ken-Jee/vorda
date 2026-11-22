(function () {
  'use strict';

  var GROUPS = [
    { key: 'mcp', name: 'MCP', icon: 'box', items: [['npm', '@modelcontextprotocol/sdk'], ['npm', '@modelcontextprotocol/inspector'], ['npm', '@modelcontextprotocol/server-filesystem'], ['npm', 'mcp-remote'], ['PyPI', 'mcp'], ['PyPI', 'fastmcp']] },
    { key: 'agents', name: 'Coding agents', icon: 'terminal', items: [['npm', '@anthropic-ai/claude-code'], ['npm', '@openai/codex'], ['npm', '@google/gemini-cli'], ['PyPI', 'aider-chat']] },
    { key: 'frameworks', name: 'Agent frameworks', icon: 'bot', items: [['PyPI', 'langchain'], ['PyPI', 'langchain-core'], ['PyPI', 'langchain-community'], ['PyPI', 'langgraph'], ['PyPI', 'llama-index-core'], ['PyPI', 'crewai'], ['PyPI', 'langflow'], ['npm', 'langchain'], ['npm', '@langchain/core']] },
    { key: 'gateways', name: 'Gateways and runners', icon: 'server', items: [['PyPI', 'litellm'], ['Go', 'github.com/ollama/ollama']] }
  ];
  // CISA lists products, not packages; these are the AI and agent platforms it may name.
  var KEV_PRODUCTS = ['litellm', 'langflow', 'langchain', 'llamaindex', 'llama index', 'ollama', 'open webui', 'mlflow', 'ray', 'n8n', 'gradio', 'comfyui', 'flowise', 'dify', 'vllm', 'anythingllm', 'model context protocol'];
  var OSV = 'https://api.osv.dev/v1/';
  var EPSS = 'https://api.first.org/data/v1/epss';
  var KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
  var DAY = 864e5, WINDOW = 30, DETAIL_CAP = 150, PAGE = 10;
  var ICONS = {
    box: '<path d="M4 8l8-4 8 4v8l-8 4-8-4z"/><path d="M4 8l8 4 8-4M12 12v8"/>',
    terminal: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 10l3 2-3 2M12 15h5"/>',
    bot: '<rect x="5" y="8" width="14" height="11" rx="2"/><path d="M12 4v4M9 13h.01M15 13h.01"/>',
    server: '<rect x="4" y="4" width="16" height="7" rx="2"/><rect x="4" y="13" width="16" height="7" rx="2"/><path d="M8 7.5h.01M8 16.5h.01"/>',
    shield: '<path d="M12 3l7 3v6c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z"/>',
    alert: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
    chev: '<path d="M9 6l6 6-6 6"/>',
    out: '<path d="M14 5h5v5M19 5l-8 8M17 14v5H5V7h5"/>'
  };

  var now = Date.now();
  var state = { osv: 'loading', capped: false, advisories: [], kev: null, kevByCve: {}, filter: 'all', shown: PAGE, totals: {} };
  var $ = function (id) { return document.getElementById(id); };
  var shortDate = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' });
  var longDate = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
  var clock = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function icon(name) {
    var s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('class', 'i');
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('aria-hidden', 'true');
    s.innerHTML = ICONS[name];
    return s;
  }
  function when(d, fmt) { return d ? (fmt || longDate).format(d) : 'Not given'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function parseDate(v) { var d = v ? new Date(v) : null; return d && !isNaN(d) ? d : null; }

  function getJSON(url, body) {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, 20000);
    var opts = { signal: ctl.signal, headers: { Accept: 'application/json' }, referrerPolicy: 'no-referrer' };
    if (body) { opts.method = 'POST'; opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    return fetch(url, opts).then(function (r) {
      clearTimeout(timer);
      if (!r.ok) throw new Error(url + ' answered ' + r.status);
      return r.json();
    }, function (e) { clearTimeout(timer); throw e; });
  }
  function pool(items, size, fn) {
    var out = new Array(items.length), next = 0;
    function worker() {
      if (next >= items.length) return Promise.resolve();
      var i = next++;
      return fn(items[i]).then(function (v) { out[i] = v; }, function () { out[i] = null; }).then(worker);
    }
    var workers = [];
    for (var k = 0; k < Math.min(size, items.length); k++) workers.push(worker());
    return Promise.all(workers).then(function () { return out; });
  }

  // ---- OSV ----
  var watched = [];
  GROUPS.forEach(function (g) { g.items.forEach(function (it) { watched.push({ eco: it[0], name: it[1], group: g.key }); }); });

  function loadOsv() {
    var started = performance.now();
    return getJSON(OSV + 'querybatch', { queries: watched.map(function (w) { return { package: { ecosystem: w.eco, name: w.name } }; }) })
      .then(function (data) {
        var seen = {}, recent = [], cut = new Date(now - WINDOW * DAY).toISOString();
        (data.results || []).forEach(function (res, i) {
          var w = watched[i];
          state.totals[w.group] = (state.totals[w.group] || 0) + (res.vulns || []).length;
          (res.vulns || []).forEach(function (v) {
            if (v.modified >= cut && !seen[v.id]) { seen[v.id] = true; recent.push({ id: v.id, modified: v.modified, watch: w }); }
          });
        });
        recent.sort(function (a, b) { return a.modified < b.modified ? 1 : -1; });
        var capped = recent.length > DETAIL_CAP;
        var picked = recent.slice(0, DETAIL_CAP);
        return pool(picked, 12, function (r) {
          return getJSON(OSV + 'vulns/' + encodeURIComponent(r.id)).then(function (d) { d._watch = r.watch; return d; });
        }).then(function (details) {
          var failed = details.filter(function (d) { return !d; }).length;
          return { details: details.filter(Boolean), failed: failed, capped: capped, updates: recent.length, ms: performance.now() - started };
        });
      });
  }

  function fixedIn(rec, w) {
    var fixed = [], ranges = [];
    (rec.affected || []).forEach(function (a) {
      if (!a.package || a.package.name !== w.name || a.package.ecosystem !== w.eco) return;
      (a.ranges || []).forEach(function (r) {
        var intro = null;
        (r.events || []).forEach(function (e) {
          if (e.introduced !== undefined) intro = e.introduced;
          if (e.fixed !== undefined) { fixed.push(e.fixed); ranges.push(rangeText(intro, e.fixed, false)); intro = null; }
          if (e.last_affected !== undefined) { ranges.push(rangeText(intro, e.last_affected, true)); intro = null; }
        });
        if (intro !== null) ranges.push(intro === '0' ? 'All versions' : 'From ' + intro + ' on');
      });
    });
    return { fixed: fixed.filter(function (v, i) { return fixed.indexOf(v) === i; }), ranges: ranges.filter(function (v, i) { return ranges.indexOf(v) === i; }) };
  }
  function rangeText(intro, end, inclusive) {
    var tail = inclusive ? 'up to and including ' + end : 'before ' + end;
    return !intro || intro === '0' ? 'Versions ' + tail : 'From ' + intro + ', ' + tail;
  }
  var SEV = { CRITICAL: 'Critical', HIGH: 'High', MODERATE: 'Moderate', MEDIUM: 'Moderate', LOW: 'Low' };

  function mergeAdvisories(details) {
    var byKey = {}, groups = [];
    details.forEach(function (d) {
      var ids = [d.id].concat(d.aliases || []);
      var hit = null;
      ids.forEach(function (id) { if (!hit && byKey[id]) hit = byKey[id]; });
      if (!hit) { hit = { records: [], ids: [] }; groups.push(hit); }
      hit.records.push(d);
      ids.forEach(function (id) { if (hit.ids.indexOf(id) < 0) hit.ids.push(id); byKey[id] = hit; });
    });
    var cut = now - WINDOW * DAY;
    return groups.map(function (g) {
      var main = g.records.filter(function (r) { return /^GHSA-/.test(r.id); })[0] || g.records.filter(function (r) { return r.summary; })[0] || g.records[0];
      var published = g.records.map(function (r) { return parseDate(r.published); }).filter(Boolean).sort(function (a, b) { return a - b; })[0];
      var sev = g.records.map(function (r) { return r.database_specific && SEV[String(r.database_specific.severity).toUpperCase()]; }).filter(Boolean)[0];
      var fx = fixedIn(main, main._watch);
      var text = (main.summary || (main.details || '').split('\n')[0].split('. ')[0].slice(0, 160) || main.id).replace(/`/g, '');
      // "MCP TypeScript SDK: HTTP transports..." -> "HTTP transports...": the package is already in the meta line.
      var cut = text.match(/^([^:]{2,48}):\s+(.{20,})$/);
      if (cut) text = /^[a-z]+(\s|$)/.test(cut[2]) ? cut[2].charAt(0).toUpperCase() + cut[2].slice(1) : cut[2];
      return {
        id: main.id, title: text, watch: main._watch, published: published, severity: sev,
        fixed: fx.fixed, ranges: fx.ranges, ids: g.ids.sort(),
        cves: g.ids.filter(function (id) { return /^CVE-/.test(id); })
      };
    }).filter(function (a) { return a.published && a.published.getTime() >= cut; })
      .sort(function (a, b) { return b.published - a.published; });
  }

  function loadEpss(advisories) {
    var cves = [];
    advisories.forEach(function (a) { a.cves.forEach(function (c) { if (cves.indexOf(c) < 0) cves.push(c); }); });
    if (!cves.length) return Promise.resolve({ count: 0, asked: 0 });
    return getJSON(EPSS + '?cve=' + encodeURIComponent(cves.slice(0, 100).join(','))).then(function (d) {
      var map = {};
      (d.data || []).forEach(function (x) { map[x.cve] = { p: Number(x.epss), pct: Number(x.percentile), date: x.date }; });
      advisories.forEach(function (a) { a.cves.forEach(function (c) { if (map[c] && (!a.epss || map[c].p > a.epss.p)) a.epss = map[c]; }); });
      return { count: Object.keys(map).length, asked: Math.min(cves.length, 100) };
    });
  }

  // ---- KEV ----
  function loadKev() {
    return getJSON(KEV).then(function (d) {
      var list = (d.vulnerabilities || []).filter(function (v) {
        var p = String(v.product || '').toLowerCase().trim(), vp = String(v.vendorProject || '').toLowerCase().trim();
        return KEV_PRODUCTS.indexOf(p) >= 0 || KEV_PRODUCTS.indexOf(vp) >= 0;
      }).sort(function (a, b) { return a.dateAdded < b.dateAdded ? 1 : -1; });
      (d.vulnerabilities || []).forEach(function (v) { state.kevByCve[v.cveID] = v; });
      state.kev = { list: list, released: parseDate(d.dateReleased), version: d.catalogVersion, count: d.count };
      return state.kev;
    });
  }

  // ---- rendering ----
  function receipt(rows) {
    var dl = el('dl', 'receipt');
    rows.forEach(function (r) {
      if (r[1] === null || r[1] === undefined || r[1] === '') return;
      dl.appendChild(el('dt', '', r[0]));
      var dd = el('dd');
      if (r[2] === 'mono') dd.appendChild(el('span', 'm', r[1]));
      else if (r[1] instanceof Node) dd.appendChild(r[1]);
      else dd.textContent = r[1];
      dl.appendChild(dd);
    });
    return dl;
  }
  function pill(href, label, go) {
    var a = el('a', 'b' + (go ? ' go' : ''), label);
    a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
    a.appendChild(icon('out'));
    a.appendChild(el('span', 'vh', ' (opens in a new tab)'));
    return a;
  }
  function row(opts) {
    var det = el('details');
    var sum = el('summary', 'row');
    var ico = el('span', 'ico' + (opts.crit ? ' crit' : ''));
    ico.appendChild(icon(opts.crit ? 'alert' : 'shield'));
    sum.appendChild(ico);
    var body = el('span', 'body');
    body.appendChild(el('span', 'title', opts.title));
    var meta = el('span', 'meta');
    opts.meta.forEach(function (m, i) {
      if (i) meta.appendChild(document.createTextNode(' · '));
      meta.appendChild(typeof m === 'string' ? document.createTextNode(m) : m);
    });
    if (opts.fig) meta.appendChild(el('span', 'when', ' · ' + opts.fig));
    body.appendChild(meta);
    sum.appendChild(body);
    if (opts.fig) sum.appendChild(el('span', 'fig', opts.fig));
    var chev = el('span', 'chev'); chev.appendChild(icon('chev')); sum.appendChild(chev);
    det.appendChild(sum);
    var open = el('div', 'open');
    open.appendChild(receipt(opts.rows));
    var foot = el('div', 'foot');
    opts.links.forEach(function (l) { foot.appendChild(pill(l[0], l[1], l[2])); });
    open.appendChild(foot);
    det.appendChild(open);
    return det;
  }
  function exploitedTag() { return el('span', 'crit', 'Known exploited'); }

  function epssText(e) {
    if (!e) return 'No score yet';
    var p = e.p * 100;
    return (p < 1 ? p.toFixed(2) : p.toFixed(1)) + '% chance of exploitation in the next 30 days';
  }

  function renderAdvisories() {
    var list = $('adv-list');
    list.replaceChildren();
    list.setAttribute('aria-busy', 'false');
    var items = state.advisories.filter(function (a) { return state.filter === 'all' || a.watch.group === state.filter; });
    if (!items.length) {
      var empty = el('div', 'empty');
      empty.appendChild(el('p', 'title', 'Nothing new in the last 30 days'));
      empty.appendChild(el('p', 'meta', state.capped ? 'None among the records this page could open. Some recently updated records were not opened, so check OSV.dev to be sure.' : 'OSV.dev has no new advisories for this group in that time.'));
      list.appendChild(empty);
    }
    items.slice(0, state.shown).forEach(function (a) {
      var kev = a.cves.map(function (c) { return state.kevByCve[c]; }).filter(Boolean)[0];
      var meta = [a.watch.name];
      if (kev) meta.push(exploitedTag());
      if (a.severity) meta.push(a.severity);
      meta.push(a.fixed.length ? 'Fixed in ' + a.fixed.slice(0, 2).join(', ') : 'No fix listed yet');
      list.appendChild(row({
        crit: !!kev, title: a.title, meta: meta, fig: shortDate.format(a.published),
        rows: [
          ['Package', a.watch.name + ' (' + a.watch.eco + ')'],
          ['Affected', a.ranges.join('; ') || 'See the advisory'],
          ['Fixed in', a.fixed.join(', ') || 'No fixed version listed yet'],
          ['Severity', a.severity || 'Not rated by the source'],
          ['Exploit forecast', a.cves.length ? epssText(a.epss) : 'No CVE number yet, so no score'],
          ['Known exploited', kev ? 'Yes, on CISA\'s list since ' + when(parseDate(kev.dateAdded)) : (state.kev ? 'Not on CISA\'s list' : 'Unknown, the list did not load')],
          ['Published', when(a.published)],
          ['Also known as', a.ids.join(', '), 'mono']
        ],
        links: [['https://osv.dev/vulnerability/' + encodeURIComponent(a.id), 'Open on OSV.dev', true]]
      }));
    });
    $('more-wrap').hidden = items.length <= state.shown;
    $('more').textContent = 'Show ' + Math.min(PAGE, items.length - state.shown) + ' more';
  }

  function renderShowing() {
    var p = $('showing');
    p.replaceChildren();
    var g = GROUPS.filter(function (x) { return x.key === state.filter; })[0];
    p.hidden = !g;
    if (!g) return;
    p.appendChild(el('span', '', 'Showing ' + g.name + ' only'));
    var b = el('button', '', 'Show all');
    b.type = 'button';
    b.addEventListener('click', function () { setFilter('all'); });
    p.appendChild(b);
  }
  function setFilter(key) {
    state.filter = state.filter === key && key !== 'all' ? 'all' : key;
    state.shown = PAGE;
    var focused = document.activeElement && document.activeElement.dataset.group;
    renderShowing(); renderGroups(); renderAdvisories();
    if (focused) document.querySelector('.mc[data-group="' + focused + '"]').focus();
  }

  function groupExploited(g) {
    // Same 30-day window as the number on the card: a new advisory on CISA's list, or a listed product added this month.
    var hit = state.advisories.some(function (a) { return a.watch.group === g.key && a.cves.some(function (c) { return state.kevByCve[c]; }); });
    if (hit || !state.kev) return hit;
    var names = g.items.map(function (it) { return it[1].split('/').pop().toLowerCase(); });
    var cut = now - WINDOW * DAY;
    return state.kev.list.some(function (v) { var d = parseDate(v.dateAdded); return d && d.getTime() >= cut && names.indexOf(String(v.product).toLowerCase()) >= 0; });
  }
  function renderGroups() {
    var box = $('groups');
    box.replaceChildren();
    GROUPS.forEach(function (g) {
      var n = state.advisories.filter(function (a) { return a.watch.group === g.key; }).length;
      var b = el('button', 'mc');
      b.type = 'button';
      b.dataset.group = g.key;
      b.setAttribute('aria-pressed', String(state.filter === g.key));
      var hd = el('span', 'hd');
      hd.appendChild(icon(g.icon));
      hd.appendChild(el('span', 'nm', g.name));
      if (state.totals[g.key] !== undefined) hd.appendChild(el('span', 't', plural(state.totals[g.key], 'record', 'records')));
      b.appendChild(hd);
      var fig = el('span', 'fig');
      var known = state.osv === 'ok';
      fig.appendChild(el('span', 'cap', known ? String(n) + (state.capped && n ? '+' : '') : '–'));
      fig.appendChild(el('span', 'unit', 'new'));
      b.appendChild(fig);
      var ex = known && groupExploited(g);
      var word = !known ? (state.osv === 'loading' ? 'Checking' : 'Not loaded') : ex ? 'Exploited' : n ? 'Active' : state.capped ? 'None found' : 'Quiet';
      b.appendChild(el('span', 'word' + (ex ? ' crit' : word === 'Quiet' ? ' ok' : ''), word));
      b.setAttribute('aria-label', g.name + ': ' + (known ? n + ' new in 30 days, ' : '') + word.toLowerCase() + '. Show only this group.');
      b.addEventListener('click', function () { setFilter(g.key); });
      box.appendChild(b);
    });
  }

  // Monotone cubic curve through the daily points (no overshoot below zero).
  function smooth(p) {
    var n = p.length, m = [], d = [], i;
    for (i = 0; i < n - 1; i++) d.push((p[i + 1][1] - p[i][1]) / (p[i + 1][0] - p[i][0]));
    m.push(d[0]);
    for (i = 1; i < n - 1; i++) m.push(d[i - 1] * d[i] <= 0 ? 0 : (d[i - 1] + d[i]) / 2);
    m.push(d[n - 2]);
    for (i = 0; i < n - 1; i++) {
      if (d[i] === 0) { m[i] = 0; m[i + 1] = 0; continue; }
      var a = m[i] / d[i], b = m[i + 1] / d[i], h = a * a + b * b;
      if (h > 9) { var t = 3 / Math.sqrt(h); m[i] = t * a * d[i]; m[i + 1] = t * b * d[i]; }
    }
    var f = function (v) { return v.toFixed(1); };
    var out = 'M' + f(p[0][0]) + ' ' + f(p[0][1]);
    for (i = 0; i < n - 1; i++) {
      var dx = (p[i + 1][0] - p[i][0]) / 3;
      out += ' C' + f(p[i][0] + dx) + ' ' + f(p[i][1] + m[i] * dx) + ' ' + f(p[i + 1][0] - dx) + ' ' + f(p[i + 1][1] - m[i + 1] * dx) + ' ' + f(p[i + 1][0]) + ' ' + f(p[i + 1][1]);
    }
    return out;
  }

  function renderChart() {
    var svg = $('hero-chart'), days = [];
    for (var i = 0; i < WINDOW; i++) days.push(0);
    state.advisories.forEach(function (a) {
      var ago = Math.floor((now - a.published.getTime()) / DAY);
      if (ago >= 0 && ago < WINDOW) days[WINDOW - 1 - ago]++;
    });
    var max = Math.max.apply(null, days.concat(1)), w = 600, h = 120, pad = 6;
    var pts = days.map(function (v, i) { return [i * w / (WINDOW - 1), h - pad - (v / max) * (h - pad * 2)]; });
    var line = smooth(pts);
    svg.innerHTML = '<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="top"/><stop offset="1" class="bot"/></linearGradient></defs>' +
      '<path d="' + line + ' L' + w + ' ' + h + ' L0 ' + h + 'Z" fill="url(#g)"/>' +
      '<path class="ln" d="' + line + '" vector-effect="non-scaling-stroke"/>';
    var busiest = days.indexOf(max);
    svg.setAttribute('aria-label', 'New advisories per day over the last 30 days: ' + days.reduce(function (s, v) { return s + v; }, 0) + ' in total, at most ' + max + ' on one day (' + shortDate.format(new Date(now - (WINDOW - 1 - busiest) * DAY)) + ').');
  }

  function renderHero() {
    var a = state.advisories;
    $('hero-count').textContent = String(a.length) + (state.capped ? '+' : '');
    $('hero-unit').textContent = (a.length === 1 ? 'new advisory' : 'new advisories') + ' in the last 30 days';
    var line = $('hero-line');
    line.replaceChildren();
    var serious = a.filter(function (x) { return x.severity === 'Critical' || x.severity === 'High'; }).length;
    var parts = [plural(serious, 'rated high or critical', 'rated high or critical'), plural(watched.length, 'package watched', 'packages watched'), 'checked at ' + clock.format(new Date())];
    if (state.kev) {
      var cut = now - WINDOW * DAY;
      var fresh = state.kev.list.filter(function (v) { var d = parseDate(v.dateAdded); return d && d.getTime() >= cut; }).length;
      parts.splice(1, 0, fresh + ' added to CISA\'s exploited list');
    }
    line.textContent = parts.join(' · ');
  }

  function renderKev() {
    var box = $('kev-list');
    box.replaceChildren();
    box.setAttribute('aria-busy', 'false');
    var list = state.kev.list;
    if (!list.length) {
      var empty = el('div', 'empty');
      empty.appendChild(el('p', 'title', 'None on the list right now'));
      empty.appendChild(el('p', 'meta', 'CISA lists no AI or agent platforms in its current catalogue.'));
      box.appendChild(empty);
      return;
    }
    var limit = box.dataset.all ? list.length : 5;
    list.slice(0, limit).forEach(function (v) {
      var added = parseDate(v.dateAdded);
      var meta = [v.cveID, v.vendorProject === v.product ? v.product : v.vendorProject + ' ' + v.product];
      if (v.knownRansomwareCampaignUse === 'Known') meta.push(el('span', 'crit', 'Used in ransomware'));
      box.appendChild(row({
        crit: true, title: v.vulnerabilityName, meta: meta, fig: added ? shortDate.format(added) : '',
        rows: [
          ['Product', v.vendorProject + ' ' + v.product],
          ['CVE', v.cveID, 'mono'],
          ['What it is', v.shortDescription],
          ['What to do', v.requiredAction],
          ['On the list since', when(added)],
          ['Ransomware', v.knownRansomwareCampaignUse === 'Known' ? 'Known to be used in ransomware' : 'Not known to be used in ransomware']
        ],
        links: [['https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.cveID), 'Read the NVD entry', true], ['https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA\'s catalogue', false]]
      }));
    });
    if (list.length > 5 && !box.dataset.all) {
      var wrap = el('div', 'row');
      var b = el('button', 'b', 'Show all ' + list.length);
      b.type = 'button';
      b.addEventListener('click', function () { box.dataset.all = '1'; renderKev(); });
      wrap.appendChild(b);
      box.appendChild(wrap);
    }
  }

  function failRows(id, title, text) {
    var box = $(id);
    box.replaceChildren();
    box.setAttribute('aria-busy', 'false');
    var empty = el('div', 'empty');
    empty.appendChild(el('p', 'title', title));
    empty.appendChild(el('p', 'meta', text));
    var b = el('button', 'b', 'Try again');
    b.type = 'button';
    b.addEventListener('click', function () { location.reload(); });
    empty.appendChild(b);
    box.appendChild(empty);
  }
  function setSource(id, cls, text) {
    var dd = $(id);
    dd.replaceChildren();
    if (cls) dd.appendChild(el('span', cls, cls === 'st-ok' ? 'Loaded. ' : 'Not loaded. '));
    dd.appendChild(document.createTextNode(text));
  }

  function renderWatch() {
    var ul = $('watch');
    GROUPS.forEach(function (g) {
      var li = el('li');
      li.appendChild(el('b', '', g.name));
      li.appendChild(el('span', 'm', g.items.map(function (it) { return it[1] + ' (' + it[0] + ')'; }).join(', ')));
      ul.appendChild(li);
    });
  }

  // ---- start ----
  renderGroups();
  renderWatch();
  $('more').addEventListener('click', function () { state.shown += PAGE; renderAdvisories(); });

  var kevDone = loadKev().then(function (k) {
    renderKev();
    setSource('src-kev', 'st-ok', 'Catalogue of ' + k.count + ' flaws, released ' + when(k.released) + ', read from CISA\'s copy on GitHub. ' + plural(k.list.length, 'entry is', 'entries are') + ' for AI and agent platforms.');
  }, function () {
    failRows('kev-list', 'CISA\'s list could not be loaded', 'Exploited status is unknown right now, not clear. Nothing is shown in its place.');
    setSource('src-kev', 'st-bad', 'The copy on GitHub did not answer, so "known exploited" cannot be shown.');
  });

  loadOsv().then(function (r) {
    state.osv = 'ok';
    state.capped = r.capped;
    state.advisories = mergeAdvisories(r.details);
    var note = 'Asked about ' + watched.length + ' packages in ' + Math.round(r.ms) + ' ms. ' + plural(state.advisories.length, 'advisory was', 'advisories were') + ' published in the last 30 days.';
    if (r.capped) note += ' Only the ' + DETAIL_CAP + ' most recently updated of ' + r.updates + ' records were opened, so the counts are a lower bound.';
    if (r.failed) note += ' ' + plural(r.failed, 'record', 'records') + ' could not be opened and are left out.';
    setSource('src-osv', 'st-ok', note);
    renderHero(); renderChart(); renderGroups(); renderAdvisories();
    return loadEpss(state.advisories).then(function (e) {
      setSource('src-epss', 'st-ok', e.asked ? 'Scores for ' + e.count + ' of ' + e.asked + ' CVE numbers.' : 'No CVE numbers to score yet.');
      renderAdvisories();
    }, function () {
      setSource('src-epss', 'st-bad', 'FIRST did not answer, so exploit forecasts are missing.');
    });
  }, function () {
    state.osv = 'failed';
    renderGroups();
    $('hero-count').textContent = '–';
    $('hero-line').textContent = 'OSV.dev could not be reached, so there is nothing to show. No sample data is put in its place.';
    failRows('adv-list', 'Advisories could not be loaded', 'OSV.dev did not answer this browser. Check your connection and try again.');
    setSource('src-osv', 'st-bad', 'OSV.dev did not answer.');
    setSource('src-epss', '', 'Not asked, because there were no advisories to score.');
  });

  kevDone.then(function () { if (state.osv === 'ok') { renderHero(); renderGroups(); renderAdvisories(); } });
}());
