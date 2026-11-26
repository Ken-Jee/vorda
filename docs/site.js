(function () {
  'use strict';

  var GROUPS = { mcp: 'MCP', agents: 'Coding agents', frameworks: 'Agent frameworks', gateways: 'Gateways and runners' };
  var SEV_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  var ICONS = {
    bell: '<path d="M6 17V11a6 6 0 0 1 12 0v6l1.5 2h-15z"/><path d="M10 21h4"/>',
    search: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',
    grid: '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>',
    book: '<path d="M5 4h11a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h11"/>',
    chev: '<path d="M9 6l6 6-6 6"/>',
    out: '<path d="M14 5h5v5M19 5l-8 8M17 14v5H5V7h5"/>',
    shield: '<path d="M12 3l7 3v6c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z"/>',
    logo: '<rect x="4" y="6" width="16" height="14" rx="2"/><path d="M4 10h16M10 6v4h4V6"/><path d="M9 15l2 2 4-4"/>'
  };
  var NAV = [
    ['index.html', 'Alerts', 'bell', 'index'],
    ['search.html', 'Search', 'search', 'search'],
    ['explore.html', 'Explore', 'grid', 'explore'],
    ['sources.html', 'Sources', 'book', 'sources']
  ];
  var page = document.body.dataset.page || 'index';
  var params = new URLSearchParams(location.search);
  var fmt = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });

  function h(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'class') n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }
  function icon(name) {
    var s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('class', 'i'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true');
    s.innerHTML = ICONS[name];
    return s;
  }
  function date(v) { var d = v ? new Date(v) : null; return d && !isNaN(d) ? fmt.format(d) : 'Unknown'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function sevEl(s) {
    return h('span', { class: 'sev sev-' + (s ? s.toLowerCase() : 'none') }, [s || 'Not rated']);
  }
  function title(a) {
    if (a.summary) return a.summary;
    return a.packages[0].name + ' advisory ' + a.id;
  }
  function markText(eco) { return eco === 'PyPI' ? 'Py' : eco === 'npm' ? 'npm' : eco; }

  /* ---------- shell ---------- */
  function buildShell() {
    var content = document.getElementById('page');
    var side = h('aside', { class: 'side' }, [
      h('a', { class: 'brand', href: 'index.html' }, [icon('logo'), 'vorda']),
      h('nav', { 'aria-label': 'Main' }, NAV.map(function (n) {
        var a = h('a', { href: n[0] }, [icon(n[2]), n[1]]);
        if (n[3] === page || (n[3] === 'search' && (page === 'advisory' || page === 'package'))) a.setAttribute('aria-current', 'page');
        return a;
      })),
      h('a', { class: 'agents', href: 'https://github.com/Ken-Jee/vorda/blob/main/docs/agents.md' }, ['For agents', icon('out')])
    ]);
    var form = h('form', { class: 'find', role: 'search', action: 'search.html', method: 'get' }, [
      icon('search'),
      h('input', { type: 'search', name: 'q', 'aria-label': 'Search the saved snapshot of advisories', placeholder: 'Search the snapshot', autocomplete: 'off', value: page === 'search' ? (params.get('q') || '') : '' })
    ]);
    var bar = h('header', { class: 'bar' }, [h('a', { class: 'brand', href: 'index.html' }, [icon('logo'), 'vorda']), form]);
    var tabs = h('nav', { class: 'tabs', 'aria-label': 'Main' }, NAV.map(function (n) {
      var a = h('a', { href: n[0] }, [icon(n[2]), n[1]]);
      if (n[3] === page || (n[3] === 'search' && (page === 'advisory' || page === 'package'))) a.setAttribute('aria-current', 'page');
      return a;
    }));
    var main = h('main', { id: 'content' }, [content]);
    var foot = h('footer', {}, [
      h('span', { text: 'vorda is open source under the MIT licence.' }),
      h('a', { class: 'ul', href: 'https://github.com/Ken-Jee/vorda', text: "Source on GitHub" }),
      h("a", { class: "ul", href: "fonts/OFL-1.1-mona-sans.txt", text: "Font licences" })
    ]);
    document.body.replaceChildren(h('a', { class: 'skip', href: '#content', text: 'Skip to the content' }), side, bar, main, foot, tabs);
  }

  /* ---------- data ---------- */
  var snapshot;
  function load() {
    if (snapshot) return snapshot;
    snapshot = fetch('data/snapshot.json').then(function (r) {
      if (!r.ok) throw new Error('status ' + r.status);
      return r.json();
    });
    return snapshot;
  }
  function failure(root) {
    root.replaceChildren(h('div', { class: 'card empty', role: 'alert' }, [
      h('p', { class: 'title', text: 'The advisory snapshot did not load.' }),
      h('p', { class: 'meta', text: 'Nothing is shown rather than a guess. Reload the page to try again, or open the live alerts page.' }),
      h('p', {}, [h('a', { class: 'b go', href: 'index.html', text: 'Open live alerts' })])
    ]));
  }
  function worst(a) {
    return a.severity;
  }
  function pkgLine(a) {
    var names = [];
    a.packages.forEach(function (p) { if (names.indexOf(p.name) < 0) names.push(p.name); });
    return names;
  }
  function haystack(a) {
    return [a.id, a.aliases.join(' '), a.summary, a.packages.map(function (p) { return p.name + ' ' + p.ecosystem; }).join(' ')].join(' ').toLowerCase();
  }

  /* ---------- shared components ---------- */
  function card(a) {
    var p = a.packages[0];
    var more = pkgLine(a).length - 1;
    return h('a', { class: 'ac', href: 'advisory.html?id=' + encodeURIComponent(a.id) }, [
      h('div', { class: 'ac-id' }, [
        h('span', { class: 'mark', 'aria-hidden': 'true', text: markText(p.ecosystem) }),
        h('span', { class: 'ac-pkg' }, [p.name + (more > 0 ? ' +' + more : ''), h('small', { text: p.ecosystem + ' · ' + GROUPS[p.group] })])
      ]),
      h('h3', { class: 'ac-t', text: title(a) }),
      h('div', { class: 'ac-m' }, [sevEl(worst(a)), h('span', { text: date(a.published) })]),
      h('p', { class: 'ac-i', text: a.id })
    ]);
  }
  function listRow(a) {
    var p = a.packages[0];
    return h('a', { class: 'row', href: 'advisory.html?id=' + encodeURIComponent(a.id) }, [
      h('span', { class: 'ico' + (a.severity === 'Critical' ? ' crit' : '') }, [icon('shield')]),
      h('span', { class: 'body' }, [
        h('span', { class: 'title', text: title(a) }),
        h('span', { class: 'meta' }, [p.name + ' · ' + (a.severity || 'Not rated') + ' · ', h('span', { class: 'when', text: date(a.published) + ' · ' }), a.id])
      ]),
      h('span', { class: 'fig', text: date(a.published) }),
      h('span', { class: 'chev' }, [icon('chev')])
    ]);
  }
  function emptyCard(headline, text) {
    return h('div', { class: 'card empty' }, [h('p', { class: 'title', text: headline }), h('p', { class: 'meta', text: text })]);
  }
  function snapNote(d) {
    return h('p', { class: 'note', text: 'Read from a snapshot of OSV.dev taken on ' + date(d.generatedAt) + '. It covers a fixed watch list of ' + d.watch.length + ' popular agent packages, not your machines. It is refreshed by a separate job, not live, so its counts can differ from the live Alerts page. A package missing from it is not a sign that it is safe.' });
  }
  function byNewest(a, b) { return (b.published || '').localeCompare(a.published || ''); }
  function rangeText(r) {
    var lo = r.introduced, up = r.fixed, last = r.last_affected;
    var from = lo && lo !== '0' ? 'From ' + lo + ' ' : '';
    if (up) return lo && lo !== '0' ? 'From ' + lo + ' up to, but not including, ' + up : 'Every version before ' + up;
    if (last) return from + (from ? 'up to and including ' : 'Up to and including ') + last;
    return lo && lo !== '0' ? 'From ' + lo + ', no fixed version listed' : 'Every version, no fixed version listed';
  }

  /* ---------- pages ---------- */
  function renderSearch(root, d) {
    var q = (params.get('q') || '').trim();
    var group = params.get('g') || 'all';
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    var hits = d.advisories.filter(function (a) {
      var t = haystack(a);
      return terms.every(function (x) { return t.indexOf(x) >= 0; });
    });
    var counts = { all: hits.length };
    Object.keys(GROUPS).forEach(function (g) { counts[g] = hits.filter(function (a) { return a.packages.some(function (p) { return p.group === g; }); }).length; });
    var shown = group === 'all' ? hits : hits.filter(function (a) { return a.packages.some(function (p) { return p.group === group; }); });
    shown.sort(byNewest);
    root.replaceChildren(
      h('h1', { text: q ? 'All results for “' + q + '”' : 'All advisories' }),
      h('section', { class: 'card summarycard', 'aria-live': 'polite' }, [
        h('span', { class: 'n', text: String(hits.length) }),
        h('p', { text: (hits.length === 1 ? 'advisory matches' : 'advisories match') + ' in this snapshot of ' + d.advisories.length + '. Snapshot taken ' + date(d.generatedAt) + '.' })
      ]),
      chipRow(counts, group, function (g) { var u = new URLSearchParams(params); if (g === 'all') u.delete('g'); else u.set('g', g); location.search = u.toString(); }),
      shown.length ? paged(shown) : emptyCard(q ? 'No advisories in this snapshot match “' + q + '”.' : 'No advisories in this group.', 'That does not mean a package is safe. The snapshot covers a fixed watch list only. Try a package name such as langchain, or open the live alerts page.'),
      snapNote(d)
    );
  }
  function chipRow(counts, group, onPick) {
    var row = h('div', { class: 'chips', role: 'group', 'aria-label': 'Group' });
    [['all', 'All']].concat(Object.keys(GROUPS).map(function (g) { return [g, GROUPS[g]]; })).forEach(function (g) {
      var b = h('button', { class: 'chip', type: 'button', 'aria-pressed': String(group === g[0]), text: g[1] + ' ' + (counts[g[0]] || 0) });
      b.addEventListener('click', function () { onPick(g[0]); });
      row.appendChild(b);
    });
    return row;
  }
  function paged(list, per) {
    per = per || 24;
    var box = h('div', {});
    var grid = h('div', { class: 'grid' });
    var wrap = h('div', { class: 'more-btn' });
    var n = 0;
    function more() {
      list.slice(n, n + per).forEach(function (a) { grid.appendChild(card(a)); });
      n += per;
      wrap.replaceChildren();
      if (n < list.length) {
        var b = h('button', { class: 'b', type: 'button', text: 'Show ' + Math.min(per, list.length - n) + ' more' });
        b.addEventListener('click', more);
        wrap.appendChild(b);
      }
    }
    more();
    box.append(grid, wrap);
    return box;
  }

  function renderExplore(root, d) {
    var state = { q: params.get('q') || '', group: params.get('g') || 'all', sev: params.get('sev') || 'all', eco: params.get('eco') || 'all', fix: params.get('fix') || 'all' };
    var results = h('div', {});
    var count = h('p', { class: 'showing', 'aria-live': 'polite' });
    function sel(label, key, opts) {
      var s = h('select', { 'aria-label': label }, opts.map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
      s.value = state[key];
      s.addEventListener('change', function () { state[key] = s.value; draw(); });
      return s;
    }
    var q = h('input', { type: 'search', 'aria-label': 'Filter advisories', placeholder: 'Filter advisories', value: state.q, autocomplete: 'off' });
    q.addEventListener('input', function () { state.q = q.value; draw(); });
    var strip = h('div', { class: 'strip' }, [
      h('div', { class: 'qpill' }, [icon('search'), q]),
      h('div', { class: 'sel' }, [
        sel('Group', 'group', [['all', 'Any group']].concat(Object.keys(GROUPS).map(function (g) { return [g, GROUPS[g]]; }))),
        sel('Severity', 'sev', [['all', 'Any severity'], ['Critical', 'Critical'], ['High', 'High'], ['Medium', 'Medium'], ['Low', 'Low'], ['none', 'Not rated']]),
        sel('Ecosystem', 'eco', [['all', 'Any ecosystem'], ['PyPI', 'PyPI'], ['npm', 'npm'], ['Go', 'Go']]),
        sel('Fix', 'fix', [['all', 'Fix or no fix'], ['yes', 'Fix listed'], ['no', 'No fix listed']])
      ])
    ]);
    function draw() {
      var terms = state.q.toLowerCase().split(/\s+/).filter(Boolean);
      var list = d.advisories.filter(function (a) {
        if (state.sev === 'none' ? a.severity : (state.sev !== 'all' && a.severity !== state.sev)) return false;
        if (state.group !== 'all' && !a.packages.some(function (p) { return p.group === state.group; })) return false;
        if (state.eco !== 'all' && !a.packages.some(function (p) { return p.ecosystem === state.eco; })) return false;
        if (state.fix !== 'all') {
          var has = a.packages.some(function (p) { return p.ranges.some(function (r) { return r.fixed; }); });
          if ((state.fix === 'yes') !== has) return false;
        }
        var t = haystack(a);
        return terms.every(function (x) { return t.indexOf(x) >= 0; });
      }).sort(byNewest);
      count.textContent = plural(list.length, 'advisory', 'advisories') + ' of ' + d.advisories.length + ' in the snapshot';
      results.replaceChildren(list.length ? paged(list) : emptyCard('No advisories match these filters.', 'Loosen a filter. An empty result here does not mean a package is safe; the snapshot covers a fixed watch list only.'));
    }
    root.replaceChildren(h('h1', { text: 'Explore advisories' }), strip, h('p', { class: 'swipe', text: 'Swipe the filters sideways for more.' }), count, results, snapNote(d));
    draw();
  }

  function receiptRows(dl, rows) {
    rows.forEach(function (r) {
      dl.appendChild(h('dt', { text: r[0] }));
      var dd = h('dd', {});
      if (r[2] === 'mono') dd.appendChild(h('span', { class: 'm', text: r[1] })); else dd.textContent = r[1];
      dl.appendChild(dd);
    });
  }
  function renderAdvisory(root, d) {
    var id = params.get('id') || '';
    var a = d.advisories.filter(function (x) { return x.id === id; })[0];
    if (!a) {
      root.replaceChildren(h('h1', { text: 'Advisory not in this snapshot' }), emptyCard(id ? 'This snapshot has no advisory with that ID.' : 'No advisory ID was given.', 'It may be newer than the snapshot, or outside the watch list. The live alerts page reads OSV.dev directly.'));
      return;
    }
    document.title = a.id + ' · vorda';
    var receipt = h('section', { class: 'card receipt-card', 'aria-labelledby': 'rcp' }, [h('h2', { id: 'rcp', class: 'vh', text: 'Advisory facts' })]);
    a.packages.forEach(function (p) {
      receipt.appendChild(h('h3', { class: 'pkg-h' }, [h('a', { class: 'ul', href: 'package.html?eco=' + encodeURIComponent(p.ecosystem) + '&name=' + encodeURIComponent(p.name), text: p.name }), ' ', h('small', { text: p.ecosystem + ' · ' + GROUPS[p.group] })]));
      var dl = h('dl', { class: 'receipt' });
      var rows = [];
      p.ranges.forEach(function (r, i) { rows.push([p.ranges.length > 1 ? 'Affected (' + (i + 1) + ')' : 'Affected', rangeText(r)]); });
      if (!p.ranges.length) rows.push(['Affected', 'The source lists versions but no range']);
      var fixes = p.ranges.map(function (r) { return r.fixed; }).filter(Boolean);
      rows.push(['Fixed in', fixes.length ? fixes.join(', ') : 'No fixed version listed']);
      receiptRows(dl, rows);
      receipt.appendChild(dl);
      if (p.versionCount) {
        var shownV = p.versions.length;
        var det = h('details', { class: 'versions' }, [
          h('summary', {}, [icon('chev'), 'Show ' + (shownV < p.versionCount ? shownV + ' of ' + p.versionCount + ' listed versions (a sample in text order, not the newest)' : plural(p.versionCount, 'listed version', 'listed versions'))]),
          h('p', { text: p.versions.join(', ') })
        ]);
        receipt.appendChild(det);
      }
    });
    var facts = h('dl', { class: 'receipt' });
    facts.className = 'receipt tail';
    receiptRows(facts, [
      ['Severity', a.severity || 'Not rated by the source'],
      ['Published', date(a.published)],
      ['Updated', date(a.modified)],
      ['Also known as', a.aliases.length ? a.aliases.join(', ') : 'No other IDs listed', a.aliases.length ? 'mono' : '']
    ]);
    receipt.appendChild(facts);
    receipt.appendChild(h('div', { class: 'foot' }, [h('a', { class: 'b go', href: 'https://osv.dev/vulnerability/' + encodeURIComponent(a.id) }, ['Open on OSV.dev', icon('out')])]));
    var side = h('section', { class: 'card', 'aria-labelledby': 'srcs' }, [
      h('h2', { id: 'srcs', class: 'flush', text: 'Where this comes from' }),
      h('p', { text: 'This record was read from OSV.dev in a snapshot taken on ' + date(d.generatedAt) + '. The text and ranges belong to the upstream database that published it.' }),
      h('p', {}, [h('a', { class: 'ul', href: 'sources.html', text: 'About these sources' })]),
      h('h2', { class: 'flush2', text: 'What it can’t tell you' }),
      h('p', { text: 'Whether a copy of this package is installed on your machines. vorda scans for that on your own computer.' })
    ]);
    var names = pkgLine(a);
    root.replaceChildren(
      h('h1', { text: title(a) }),
      h('p', { class: 'sub', text: names.join(', ') }),
      h('div', { class: 'two' }, [receipt, side])
    );
  }

  function renderPackage(root, d) {
    var eco = params.get('eco') || '', name = params.get('name') || '';
    var list = d.advisories.filter(function (a) { return a.packages.some(function (p) { return p.ecosystem === eco && p.name === name; }); }).sort(byNewest);
    var watched = d.watch.filter(function (w) { return w.ecosystem === eco && w.name === name; })[0];
    if (!watched) {
      root.replaceChildren(h('h1', { text: 'Package not on the watch list' }), emptyCard('This package is not on the watch list.', 'Only a fixed list of popular agent packages is covered. That does not mean the package is safe.'));
      return;
    }
    document.title = name + ' · vorda';
    var best = list.reduce(function (m, a) { return Math.max(m, SEV_RANK[a.severity] || 0); }, 0);
    var bestName = Object.keys(SEV_RANK).filter(function (k) { return SEV_RANK[k] === best; })[0];
    root.replaceChildren(
      h('h1', { text: name }),
      h('p', { class: 'sub', text: eco + ' · ' + GROUPS[watched.group] }),
      h('section', { class: 'card summarycard' }, [
        h('span', { class: 'n', text: String(list.length) }),
        h('p', { text: list.length ? (list.length === 1 ? 'advisory' : 'advisories') + ' in this snapshot' + (bestName ? ', highest rated ' + bestName : '') + '. Taken ' + date(d.generatedAt) + '.' : 'No advisories for this package in the snapshot taken ' + date(d.generatedAt) + '. That is not proof it is safe.' })
      ]),
      list.length ? h('div', { class: 'rows' }, list.map(listRow)) : emptyCard('Nothing listed.', 'The snapshot may be out of date. Check the live alerts page.'),
      snapNote(d)
    );
  }

  function renderSources(root, d) {
    function src(name, text, link, linkText) {
      return h('section', { class: 'card' }, [
        h('h2', { class: 'flush', text: name }),
        h('p', { text: text }),
        h('p', {}, [h('a', { class: 'ul', href: link, text: linkText })])
      ]);
    }
    var packages = h('section', { class: 'card' }, [h('h2', { class: 'flush', text: 'The watch list' }), h('p', { text: d.watch.length + ' packages in four groups.' })]);
    var ul = h('ul', { class: 'watch' });
    Object.keys(GROUPS).forEach(function (g) {
      ul.appendChild(h('li', {}, [h('b', { text: GROUPS[g] }), h('span', { class: 'm' }, d.watch.filter(function (w) { return w.group === g; }).map(function (w) {
        return h('span', { class: 'wi' }, [w.ecosystem + ' · ', h('a', { class: 'ul', href: 'package.html?eco=' + encodeURIComponent(w.ecosystem) + '&name=' + encodeURIComponent(w.name), text: w.name })]);
      }))]));
    });
    packages.appendChild(ul);
    root.replaceChildren(
      h('h1', { text: 'Where the data comes from' }),
      h('p', { class: 'sub', text: 'Every figure on this site is read from a public feed. Nothing is scored or rewritten by vorda.' }),
      h('div', { class: 'srcs' }, [
        src('OSV.dev', 'Advisories for the search, explore, advisory and package pages come from a snapshot of OSV.dev taken on ' + date(d.generatedAt) + ' (' + plural(d.advisories.length, 'record', 'records') + '). The snapshot is a file in this site, refreshed by a separate job rather than read live.', 'https://osv.dev/', 'osv.dev'),
        src('Live alerts', 'The Alerts page asks OSV.dev, FIRST EPSS and CISA’s known-exploited list directly from your browser each time it opens.', 'index.html', 'Open live alerts'),
        src('CISA KEV', 'The known-exploited list is read from the copy CISA publishes on GitHub, because CISA’s own site blocks reads from other pages.', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'cisa.gov'),
        src('FIRST EPSS', 'A forecast of how likely a flaw is to be exploited in the next 30 days. Brand-new flaws often have no score yet.', 'https://www.first.org/epss/', 'first.org/epss')
      ]),
      packages,
      h('p', { class: 'note', text: 'This site does not look at your machines and stores nothing in your browser. Like any website, the host and the feeds see your IP address.' })
    );
  }

  /* ---------- start ---------- */
  buildShell();
  var root = document.getElementById('page');
  var renderers = { search: renderSearch, explore: renderExplore, advisory: renderAdvisory, package: renderPackage, sources: renderSources };
  if (renderers[page]) {
    load().then(function (d) { renderers[page](root, d); }, function () { failure(root); });
  }
})();
