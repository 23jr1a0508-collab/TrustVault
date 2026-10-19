(() => {
  "use strict";

  const app = document.getElementById("app");
  const toastRegion = document.getElementById("toast-region");
  const API_ROOT = "/trustvault-api";
  const state = {
    session: null,
    csrfToken: "",
    view: "dashboard",
    loading: false,
    pageError: "",
    dashboard: null,
    documents: [],
    users: [],
    auditLogs: [],
    selectedPermissionDoc: "",
    permissions: [],
    permissionUsers: [],
    filters: { q: "", category: "", owner: "", from: "", to: "" },
    auditFilters: { q: "", action: "" },
    modal: null,
    sidebarOpen: false,
    loadSequence: 0
  };

  const icons = {
    vault: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4.5 8.5h15v10a2 2 0 0 1-2 2h-11a2 2 0 0 1-2-2v-10Z" stroke="currentColor" stroke-width="1.7"/><path d="M3.5 5.5h17v3h-17zM9 5.5V3.8h6v1.7M12 11v2.5m0 0a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 0 0 0-3.6Z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    dashboard: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="3.5" y="3.5" width="7" height="7" rx="1.3" stroke="currentColor" stroke-width="1.7"/><rect x="13.5" y="3.5" width="7" height="5" rx="1.3" stroke="currentColor" stroke-width="1.7"/><rect x="13.5" y="11.5" width="7" height="9" rx="1.3" stroke="currentColor" stroke-width="1.7"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.3" stroke="currentColor" stroke-width="1.7"/></svg>',
    file: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 3.8h8l4 4v12.4H6V3.8Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M14 3.8v4h4M9 12h6m-6 3.5h6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    people: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M16 20v-1.6a3.4 3.4 0 0 0-3.4-3.4H6.4A3.4 3.4 0 0 0 3 18.4V20m6.5-8a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm7-6.5a3.5 3.5 0 0 1 0 6.8m1 4.7h1.1a3.4 3.4 0 0 1 3.4 3.4V20" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 21s7-3.3 7-9V5l-7-2-7 2v7c0 5.7 7 9 7 9Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="m9 12 2 2 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    history: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3.5 12a8.5 8.5 0 1 0 2.1-5.6L3.5 8.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path d="M3.5 4.5v4h4m4.5-1v5l3 2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="10.8" cy="10.8" r="6.8" stroke="currentColor" stroke-width="1.8"/><path d="m16 16 4.5 4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    upload: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 15.5V4m0 0L7.5 8.5M12 4l4.5 4.5M4 15.5v3A1.5 1.5 0 0 0 5.5 20h13a1.5 1.5 0 0 0 1.5-1.5v-3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 4v11m0 0 4.5-4.5M12 15l-4.5-4.5M4 16v3.5h16V16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    edit: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m14 5 5 5M4 20l4.2-.9L19 8.3a2.1 2.1 0 0 0-3-3L5.2 16.1 4 20Z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    trash: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4.5 7h15m-13.5 0 .8 13h10.4L18 7M9 7V4h6v3m-4 4v5m2-5v5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    close: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    more: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="5" cy="12" r="1.2" fill="currentColor"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/><circle cx="19" cy="12" r="1.2" fill="currentColor"/></svg>',
    link: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m9.5 14.5 5-5m-7.8 8.3a4 4 0 0 1 0-5.7l2.1-2.1a4 4 0 0 1 5.7 0m-1.9-2.8a4 4 0 0 1 5.7 0 4 4 0 0 1 0 5.7l-2.1 2.1a4 4 0 0 1-5.7 0" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="4.5" y="10" width="15" height="11" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    alert: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 2.8 19h18.4L12 3Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 9v4m0 3h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    clock: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v5l3 2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="m5 12.5 4.5 4L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4 6.5h16M4 12h16M4 17.5h16" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    empty: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 4h8l4 4v12H6V4Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M14 4v4h4m-8 4h4m-4 3.5h4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>'
  };

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
  const isAdmin = () => state.session?.user?.role === "administrator";
  const currentUser = () => state.session?.user;
  const canManageDocument = (doc) => isAdmin() || String(doc?.owner?.id) === String(currentUser()?.id);
  const initials = (name) => String(name || "?").trim().split(/\s+/).slice(0, 2).map((part) => part[0] || "").join("").toUpperCase();
  const fmtDate = (value, withTime = false) => {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(value);
    return new Intl.DateTimeFormat(undefined, withTime
      ? { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }
      : { month: "short", day: "numeric", year: "numeric" }).format(date);
  };
  const fmtSize = (bytes) => {
    if (bytes === null || bytes === undefined || Number.isNaN(Number(bytes))) return "—";
    const size = Number(bytes);
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
    return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };
  const humanize = (value) => String(value || "Activity").replace(/[_-]+/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
  const queryString = (params) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== "" && value !== null && value !== undefined) query.set(key, value);
    });
    return query.toString();
  };

  class RequestError extends Error {
    constructor(message, status = 0, detail = "") {
      super(message);
      this.name = "RequestError";
      this.status = status;
      this.detail = detail;
    }
  }

  function apiPath(path) {
    return path.replace(/^\/api(?=\/)/, API_ROOT);
  }

  function handleUnauthorized() {
    if (!state.session) return;
    state.session = null;
    state.csrfToken = "";
    state.modal = null;
    state.view = "login";
    state.pageError = "Your session has expired. Sign in again to continue.";
    render();
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const requestPath = apiPath(path);
    const headers = new Headers(options.headers || {});
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && requestPath !== `${API_ROOT}/auth/login`) {
      headers.set("X-CSRF-Token", state.csrfToken);
      if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
    }
    let response;
    try {
      response = await fetch(requestPath, { ...options, method, headers, credentials: "same-origin" });
    } catch {
      throw new RequestError("Could not reach TrustVault. Check your connection and try again.");
    }
    if (response.status === 401) {
      handleUnauthorized();
      throw new RequestError("Your session has expired. Sign in again.", 401);
    }
    if (!response.ok) {
      let message = `Request failed (${response.status}).`;
      let detail = "";
      try {
        const body = await response.json();
        detail = body.detail || body.message || body.error || "";
        if (typeof detail === "object") detail = JSON.stringify(detail);
        if (detail) message = String(detail);
      } catch {
        try { detail = await response.text(); } catch { detail = ""; }
        if (detail) message = detail;
      }
      if (response.status === 403) message = `Access denied: ${message}`;
      if (response.status === 422 || response.status === 400) message = `Please check the submitted information: ${message}`;
      throw new RequestError(message, response.status, detail);
    }
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) return response.json();
    return response;
  }

  const getJSON = (url) => apiRequest(url);
  const mutateJSON = (url, method, payload) => apiRequest(url, {
    method,
    body: payload === undefined ? undefined : JSON.stringify(payload)
  });

  function toast(message, type = "success") {
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.innerHTML = `${icons[type === "error" ? "alert" : "check"]}<span>${esc(message)}</span>`;
    toastRegion.appendChild(node);
    window.setTimeout(() => node.remove(), 3800);
  }

  const viewTitles = {
    dashboard: ["Overview", "Your secure handoff workspace"],
    documents: ["Documents", "Sensitive files, shared deliberately."],
    permissions: ["Access & permissions", "Named reviewers. Clear boundaries."],
    audit: ["Audit trail", "A transparent record of every access change."],
    users: ["User management", "Manage who can enter your workspace."]
  };

  function navItems() {
    const items = [
      ["dashboard", "Overview", icons.dashboard],
      ["documents", "Documents", icons.file]
    ];
    if (state.session?.user?.role !== "viewer") items.push(["permissions", "Access & permissions", icons.shield]);
    if (isAdmin()) {
      items.push(["audit", "Audit trail", icons.history]);
      items.push(["users", "User management", icons.people]);
    }
    return items;
  }

  function sidebarMarkup() {
    const user = currentUser();
    return `<div class="mobile-sidebar-backdrop ${state.sidebarOpen ? "visible" : ""}" data-action="close-sidebar"></div>
      <aside class="sidebar ${state.sidebarOpen ? "open" : ""}" aria-label="Main navigation">
        <div class="brand">${icons.vault}<span class="brand-word">Trust<span>Vault</span></span></div>
        <div class="workspace-label">Workspace</div>
        <nav class="nav-list" aria-label="Workspace">
          ${navItems().map(([key, label, icon]) => `<button class="nav-item ${state.view === key ? "active" : ""}" data-nav="${key}" ${state.view === key ? 'aria-current="page"' : ""}>${icon}<span>${label}</span></button>`).join("")}
        </nav>
        <div class="nav-divider"></div>
        <div class="workspace-label">Workspace standards</div>
        <div class="security-note"><div class="security-note-head">${icons.shield}<span>Controlled access</span></div><p>Each candidate file is shared with named reviewers, not an open link.</p></div>
        <div class="sidebar-spacer"></div>
        <div class="profile-menu">
          <div class="avatar" aria-hidden="true">${esc(initials(user?.display_name || user?.username))}</div>
          <div class="profile-copy"><div class="profile-name">${esc(user?.display_name || user?.username)}</div><div class="profile-role">${esc(user?.role)}</div></div>
          <button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icons.close}</button>
        </div>
      </aside>`;
  }

  function shellMarkup() {
    const [title] = viewTitles[state.view] || ["Workspace"];
    return `${sidebarMarkup()}
      <div class="main-area">
        <header class="topbar">
          <div class="crumb"><button class="icon-button mobile-menu" data-action="open-sidebar" aria-label="Open navigation">${icons.menu}</button><span>Workspace</span>${icons.file}<strong>${esc(title)}</strong></div>
          <div class="topbar-right"><div class="top-meta"><span class="secure-dot"></span><span>Secure session</span></div><button class="icon-button" data-action="logout" aria-label="Sign out" title="Sign out">${icons.close}</button></div>
        </header>
        <div id="view-root"></div>
      </div>`;
  }

  function loginMarkup() {
    const error = state.pageError ? alertMarkup(state.pageError) : "";
    return `<div class="login-screen">
      <section class="login-aside" aria-label="TrustVault information">
        <div class="brand">${icons.vault}<span class="brand-word">Trust<span>Vault</span></span></div>
        <div class="login-message"><span class="eyebrow">Secure candidate handoff</span><h1>Share the right file.<br>With the right people.</h1><p>A focused workspace for hiring teams to move sensitive candidate documents with confidence and a clear record of every access change.</p></div>
        <div class="login-quote">Private by default. Visible by design.<span>TrustVault workspace security</span></div>
      </section>
      <section class="login-main">
        <form class="login-card" id="login-form">
          <span class="eyebrow">Welcome back</span><h2>Sign in to TrustVault</h2><p class="login-intro">Use your workspace credentials to continue.</p>
          <div id="login-alert">${error}</div>
          <div class="form-row"><label for="login-username">Username</label><input class="field" id="login-username" name="username" autocomplete="username" required autofocus></div>
          <div class="form-row"><label for="login-password">Password</label><input class="field" id="login-password" name="password" type="password" autocomplete="current-password" required></div>
          <button class="button button-primary" type="submit">Sign in <span aria-hidden="true">→</span></button>
          <div class="login-foot"><span>${icons.lock} Encrypted session · Access is logged</span></div>
        </form>
      </section>
    </div>`;
  }

  function alertMarkup(message, info = false) {
    return `<div class="inline-alert ${info ? "info" : ""}" role="alert">${icons.alert}<span>${esc(message)}</span></div>`;
  }

  function pageFrame(content, heading, subtitle, action = "") {
    return `<main class="page">
      <div class="page-heading"><div><span class="eyebrow">TrustVault / ${esc(viewTitles[state.view]?.[0] || "Workspace")}</span><h1>${esc(heading)}</h1><p class="page-subtitle">${esc(subtitle)}</p></div>${action}</div>
      ${state.pageError ? `${alertMarkup(state.pageError)}<button class="button button-secondary button-small" data-action="retry-view" style="margin:-5px 0 14px">Retry loading</button>` : ""}
      ${content}
    </main>`;
  }

  function loadingMarkup(rows = 4) {
    return `<div class="panel loading-state" role="status" aria-label="Loading"><span class="sr-only">Loading content</span>${Array.from({ length: rows }, () => '<div class="skeleton"></div>').join("")}</div>`;
  }

  function emptyMarkup(title, copy, action = "") {
    return `<div class="table-empty"><div class="empty-visual">${icons.empty}</div><h3>${esc(title)}</h3><p>${esc(copy)}</p>${action}</div>`;
  }

  function dashboardMarkup() {
    if (!state.dashboard) {
      return pageFrame(loadingMarkup(5), "Your workspace, at a glance", "A clear view of what is shared and what has changed.");
    }
    const stats = state.dashboard.stats || {};
    const statData = [
      ["documents", "Documents", icons.file, "Files in your workspace"],
      ["shared", "Shared files", icons.link, "Currently shared with reviewers"],
      ["downloads", "Downloads", icons.download, "Recorded file downloads"],
      ["users", "Workspace users", icons.people, "Named workspace members"]
    ];
    const statCards = statData.map(([key, label, icon, caption]) => `<article class="stat-card"><div class="stat-top"><span>${label}</span><span class="stat-icon">${icon}</span></div><div class="stat-value">${esc(stats[key] ?? "—")}</div><div class="stat-caption">${caption}</div></article>`).join("");
    const activities = Array.isArray(state.dashboard.recent_activity) ? state.dashboard.recent_activity : [];
    const activityRows = activities.length ? activities.slice(0, 7).map((entry) => {
      const action = humanize(entry.action || entry.event || "Access event");
      const actor = entry.actor?.display_name || entry.actor?.username || "";
      const target = entry.target || entry.document_name || entry.metadata?.name || "";
      return `<div class="activity-row"><div class="activity-mark">${activityIcon(entry.action)}</div><div class="activity-main"><strong>${esc(actor || action)}</strong> ${actor ? esc(action.toLowerCase()) : ""}${target ? ` <strong>${esc(target)}</strong>` : ""}<span class="activity-secondary">${esc(entry.metadata?.detail || entry.metadata?.level || "Workspace event")}</span></div><time class="activity-time">${esc(fmtDate(entry.created_at, true))}</time></div>`;
    }).join("") : `<div class="activity-list">${emptyMarkup("No recent activity", "Access events will appear here as documents are shared and reviewed.")}</div>`;
    const contents = `<section class="stat-grid" aria-label="Workspace statistics">${statCards}</section>
      <section class="dashboard-grid">
        <article class="panel"><header class="panel-header"><div><h2 class="panel-title">Recent activity</h2><p class="panel-subtitle">The latest actions in your workspace</p></div>${isAdmin() ? '<button class="text-link" data-nav="audit">View audit trail</button>' : ""}</header>${activityRows}</article>
        <aside class="panel integrity-panel"><div class="integrity-orbit">${icons.shield}</div><h2>Every handoff stays accountable.</h2><p>Access is tied to a named reviewer. Changes to sharing and file access are recorded in your workspace audit trail.</p>${isAdmin() ? '<button class="button button-secondary button-small" data-nav="audit">Review audit trail</button>' : currentUser()?.role !== "viewer" ? '<button class="button button-secondary button-small" data-nav="permissions">Manage access</button>' : '<button class="button button-secondary button-small" data-nav="documents">Browse documents</button>'}<div class="mini-divider"></div><div class="mini-metric"><span>Session status</span><strong>ACTIVE</strong></div><div class="mini-metric"><span>Current role</span><strong>${esc(userRoleLabel())}</strong></div></aside>
      </section>`;
    return pageFrame(contents, "Your workspace, at a glance", "A clear view of what is shared and what has changed.", `<button class="button button-primary" data-nav="documents">${icons.file} Browse documents</button>`);
  }

  function activityIcon(action = "") {
    const word = String(action).toLowerCase();
    if (word.includes("download")) return icons.download;
    if (word.includes("permission") || word.includes("share") || word.includes("access")) return icons.shield;
    if (word.includes("delete") || word.includes("remove")) return icons.trash;
    return icons.file;
  }

  function userRoleLabel() {
    const role = currentUser()?.role || "";
    return role ? role.charAt(0).toUpperCase() + role.slice(1) : "—";
  }

  function documentToolbar() {
    const f = state.filters;
    return `<form class="toolbar" id="document-filters">
      <label class="search-field"><span class="sr-only">Search documents</span>${icons.search}<input class="field" name="q" value="${esc(f.q)}" placeholder="Search by document name" type="search"></label>
      <label class="sr-only" for="filter-category">Category</label><input class="field" id="filter-category" name="category" value="${esc(f.category)}" placeholder="Category" aria-label="Filter by category" style="max-width:150px">
      <label class="sr-only" for="filter-owner">Owner</label><input class="field" id="filter-owner" name="owner" value="${esc(f.owner)}" placeholder="Owner" aria-label="Filter by owner" style="max-width:145px">
      <label class="sr-only" for="filter-from">From date</label><input class="field" id="filter-from" name="from" type="date" value="${esc(f.from)}" aria-label="From date" style="max-width:145px">
      <label class="sr-only" for="filter-to">To date</label><input class="field" id="filter-to" name="to" type="date" value="${esc(f.to)}" aria-label="To date" style="max-width:145px">
      <button class="button button-secondary button-small" type="submit">Apply</button>
      <button class="button button-quiet button-small" type="button" data-action="clear-doc-filters">Clear</button>
    </form>`;
  }

  function documentRows(documents, showPermissions = false) {
    if (!documents.length) {
      const canUpload = currentUser()?.role !== "viewer";
      return `<tr><td colspan="6"><div class="table-empty"><div class="empty-visual">${icons.empty}</div><h3>No documents found</h3><p>${state.filters.q || state.filters.category || state.filters.owner || state.filters.from || state.filters.to ? "Try adjusting your search filters." : "When a file is added to your workspace, it will appear here."}</p>${canUpload && !showPermissions ? '<button class="button button-primary button-small" data-action="upload">Add a document</button>' : ""}</div></td></tr>`;
    }
    return documents.map((doc) => {
      const manageable = canManageDocument(doc);
      const id = esc(doc.id);
      const name = esc(doc.name || "Untitled document");
      const icon = icons.file;
      const ownerName = esc(doc.owner?.display_name || "Unknown");
      const permission = doc.permission?.level || doc.permission || "";
      return `<tr>
        <td><div class="doc-name"><span class="file-icon">${icon}</span><span><button class="text-link file-name" data-action="details" data-id="${id}" style="padding:0;text-align:left">${name}</button><span class="file-meta">${esc(doc.content_type || "Document")} · ${esc(fmtSize(doc.size))}</span></span></div></td>
        <td><span class="category-pill">${esc(doc.category || "Uncategorized")}</span></td>
        <td>${ownerName}</td>
        <td>${esc(fmtDate(doc.created_at))}</td>
        <td>${permission ? `<span class="level-pill">${esc(humanize(permission))}</span>` : manageable ? '<span class="file-meta">Owner</span>' : '<span class="file-meta">Shared with you</span>'}</td>
        <td><div class="table-actions">
          <button class="icon-button" data-action="download" data-id="${id}" aria-label="Download ${name}" title="Download">${icons.download}</button>
          ${manageable ? `<button class="icon-button" data-action="permissions-for" data-id="${id}" aria-label="Manage access for ${name}" title="Manage access">${icons.shield}</button><button class="icon-button" data-action="edit-document" data-id="${id}" aria-label="Edit ${name}" title="Edit">${icons.edit}</button><button class="icon-button" data-action="delete-document" data-id="${id}" aria-label="Delete ${name}" title="Delete">${icons.trash}</button>` : ""}
        </div></td>
      </tr>`;
    }).join("");
  }

  function documentsMarkup() {
    const canUpload = currentUser()?.role !== "viewer";
    const action = canUpload ? `<button class="button button-primary" data-action="upload">${icons.upload} Upload document</button>` : "";
    if (state.loading) return pageFrame(loadingMarkup(5), "Documents", viewTitles.documents[1], action);
    const table = `<section class="panel"><div class="table-wrap"><table class="data-table"><thead><tr><th>Document</th><th>Category</th><th>Owner</th><th>Added</th><th>Access</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${documentRows(state.documents)}</tbody></table></div></section>`;
    return pageFrame(`${documentToolbar()}${table}`, "Documents", viewTitles.documents[1], action);
  }

  function permissionsMarkup() {
    if (state.loading) return pageFrame(loadingMarkup(4), "Manage document access", "Choose a file to review its named recipients and access level.");
    const docs = state.documents.filter((doc) => canManageDocument(doc));
    const selected = docs.find((doc) => String(doc.id) === String(state.selectedPermissionDoc));
    const selector = `<section class="panel"><header class="panel-header"><div><h2 class="panel-title">Choose a document</h2><p class="panel-subtitle">${docs.length ? "Access is managed one file at a time." : "Only documents you own can be managed here."}</p></div></header>
      <div style="padding:16px 19px"><label class="sr-only" for="permission-document">Select a document</label><select class="select" id="permission-document" style="width:100%;max-width:480px"><option value="">Select a document…</option>${docs.map((doc) => `<option value="${esc(doc.id)}" ${String(doc.id) === String(state.selectedPermissionDoc) ? "selected" : ""}>${esc(doc.name)} · ${esc(doc.owner?.display_name || "")}</option>`).join("")}</select></div></section>`;
    let accessPanel = "";
    if (selected) {
      if (state.permissionUsers.length === 0 && state.permissions.length === 0) {
        accessPanel = `<section class="panel" style="margin-top:14px">${emptyMarkup("No named reviewers yet", "Grant access to a specific workspace user. Each change is recorded.")}</section>`;
      } else {
        const listed = state.permissions.map((permission) => {
          const user = permission.user || {};
          const level = permission.level === "edit" ? "edit" : "read";
          return `<div class="permission-person"><div class="avatar">${esc(initials(user.display_name || user.username))}</div><div class="permission-person-copy"><div class="permission-person-name">${esc(user.display_name || user.username || "Workspace member")}</div><div class="permission-person-email">${esc(user.username || "")}</div></div><label class="sr-only" for="level-${esc(user.id)}">Access level for ${esc(user.display_name || user.username)}</label><select class="select" id="level-${esc(user.id)}" data-action="change-permission" data-document-id="${esc(selected.id)}" data-user-id="${esc(user.id)}"><option value="read" ${level === "read" ? "selected" : ""}>Can view</option><option value="edit" ${level === "edit" ? "selected" : ""}>Can edit</option></select><button class="icon-button" data-action="remove-permission" data-document-id="${esc(selected.id)}" data-user-id="${esc(user.id)}" aria-label="Remove access for ${esc(user.display_name || user.username)}" title="Remove access">${icons.trash}</button></div>`;
        }).join("");
        accessPanel = `<section class="panel" style="margin-top:14px"><header class="panel-header"><div><h2 class="panel-title">People with access</h2><p class="panel-subtitle">${esc(selected.name)}</p></div><span class="category-pill">${state.permissions.length} named ${state.permissions.length === 1 ? "reviewer" : "reviewers"}</span></header><div style="padding:0 19px">${listed || emptyMarkup("No named reviewers yet", "Add a workspace member below.")}<div class="permission-add"><div class="permission-add-title">Grant access</div><form class="permission-add-form" id="permission-add-form" data-document-id="${esc(selected.id)}"><label class="sr-only" for="permission-user">Select a reviewer</label><select class="select" id="permission-user" name="user_id" required><option value="">Choose a workspace member…</option>${state.permissionUsers.filter((user) => !state.permissions.some((p) => String(p.user?.id) === String(user.id))).map((user) => `<option value="${esc(user.id)}">${esc(user.display_name || user.username)}${user.role ? ` · ${esc(user.role)}` : ""}</option>`).join("")}</select><label class="sr-only" for="permission-level">Access level</label><select class="select" id="permission-level" name="level" aria-label="Access level"><option value="read">Can view</option><option value="edit">Can edit</option></select><button class="button button-primary button-small" type="submit">${icons.link} Grant access</button></form></div></div></section>`;
      }
    } else if (!docs.length) {
      accessPanel = `<section class="panel" style="margin-top:14px">${emptyMarkup("No manageable documents", "Upload a document to start a named handoff.")}</section>`;
    }
    return pageFrame(`${selector}${accessPanel}`, "Manage document access", "Choose a file to review its named recipients and access level.");
  }

  function auditMarkup() {
    if (state.loading) return pageFrame(loadingMarkup(6), "Audit trail", viewTitles.audit[1]);
    const filters = state.auditFilters;
    const toolbar = `<form class="toolbar" id="audit-filters"><label class="search-field">${icons.search}<span class="sr-only">Search audit trail</span><input class="field" type="search" name="q" value="${esc(filters.q)}" placeholder="Search people, files or events"></label><label class="sr-only" for="audit-action">Filter by action</label><input class="field" id="audit-action" name="action" value="${esc(filters.action)}" placeholder="Action" aria-label="Filter by action" style="max-width:180px"><button class="button button-secondary button-small" type="submit">Apply filters</button><button class="button button-quiet button-small" type="button" data-action="clear-audit-filters">Clear</button></form>`;
    const rows = state.auditLogs.length ? state.auditLogs.map((entry) => `<tr>
      <td><span class="category-pill">${esc(humanize(entry.action))}</span></td>
      <td>${esc(entry.actor?.display_name || "System")}<span class="audit-target">${esc(entry.target || entry.metadata?.target || "—")}</span></td>
      <td>${esc(entry.metadata?.detail || entry.metadata?.level || entry.metadata?.name || "—")}</td>
      <td><time>${esc(fmtDate(entry.created_at, true))}</time></td>
      <td><span class="hash" title="${esc(entry.integrity_hash || "")}">${esc(entry.integrity_hash || "—")}</span></td>
    </tr>`).join("") : `<tr><td colspan="5">${emptyMarkup("No audit events found", filters.q || filters.action ? "Try widening your search filters." : "Access and document events will be recorded here.")}</td></tr>`;
    return pageFrame(`<div class="audit-summary">${icons.shield}<span><strong>Accountability by default.</strong> Each event retains its actor, target, timestamp and integrity hash.</span></div>${toolbar}<section class="panel"><div class="table-wrap"><table class="data-table"><thead><tr><th>Event</th><th>Actor / target</th><th>Details</th><th>Timestamp</th><th>Integrity hash</th></tr></thead><tbody>${rows}</tbody></table></div></section>`, "Audit trail", viewTitles.audit[1]);
  }

  function usersMarkup() {
    const action = `<button class="button button-primary" data-action="add-user">${icons.people} Add user</button>`;
    if (state.loading) return pageFrame(loadingMarkup(5), "Workspace users", viewTitles.users[1], action);
    const rows = state.users.length ? state.users.map((user) => {
      const self = String(user.id) === String(currentUser()?.id);
      const roleClass = user.role === "administrator" ? "admin" : user.role === "owner" ? "owner" : "viewer";
      return `<tr><td><div class="doc-name"><div class="avatar" style="background:#eaf0f8;color:#55709a">${esc(initials(user.display_name || user.username))}</div><span><span class="file-name">${esc(user.display_name || user.username)}</span><span class="file-meta">${esc(user.username)}</span></span></div></td><td><span class="role-pill ${roleClass}">${esc(humanize(user.role))}</span></td><td><span class="status-pill" style="${user.active === false ? "color:#a74a4f;background:#fff0f0" : ""}">${user.active === false ? "Inactive" : "Active"}</span></td><td>${self ? '<span class="file-meta">You</span>' : `<button class="icon-button" data-action="delete-user" data-id="${esc(user.id)}" data-name="${esc(user.display_name || user.username)}" aria-label="Remove ${esc(user.display_name || user.username)}" title="Remove user">${icons.trash}</button>`}</td></tr>`;
    }).join("") : `<tr><td colspan="4">${emptyMarkup("No workspace users", "Users will appear here when they have been added.")}</td></tr>`;
    return pageFrame(`<section class="panel"><div class="table-wrap"><table class="data-table"><thead><tr><th>Person</th><th>Role</th><th>Status</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows}</tbody></table></div></section>`, "Workspace users", viewTitles.users[1], action);
  }

  function modalMarkup() {
    if (!state.modal) return "";
    const { type, document: doc } = state.modal;
    const close = `<button class="icon-button" type="button" data-action="close-modal" aria-label="Close">${icons.close}</button>`;
    if (type === "upload") return `<div class="modal-backdrop" data-action="backdrop-close"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><h2 id="modal-title">Upload a document</h2><p>Add a sensitive candidate file to your workspace.</p></div>${close}</header><form id="upload-form"><div class="modal-body"><div id="modal-alert"></div><label class="upload-drop" for="upload-file"><span><span class="upload-icon">${icons.upload}</span><strong id="upload-file-name">Choose a file to upload</strong><span>File contents remain inside TrustVault.</span></span><input id="upload-file" name="file" type="file" required></label><div class="form-grid" style="margin-top:16px"><div class="form-row"><label for="upload-name">Document name</label><input class="field" id="upload-name" name="name" required placeholder="e.g. Candidate portfolio"></div><div class="form-row"><label for="upload-category">Category</label><input class="field" id="upload-category" name="category" required placeholder="e.g. Resume"></div></div><div class="modal-footer"><button class="button button-secondary" type="button" data-action="close-modal">Cancel</button><button class="button button-primary" type="submit">${icons.upload} Upload file</button></div></div></form></section></div>`;
    if (type === "edit") return `<div class="modal-backdrop" data-action="backdrop-close"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><h2 id="modal-title">Edit document details</h2><p>Update the name or filing category.</p></div>${close}</header><form id="edit-form" data-id="${esc(doc.id)}"><div class="modal-body"><div id="modal-alert"></div><div class="form-row"><label for="edit-name">Document name</label><input class="field" id="edit-name" name="name" value="${esc(doc.name)}" required></div><div class="form-row"><label for="edit-category">Category</label><input class="field" id="edit-category" name="category" value="${esc(doc.category || "")}" required></div><div class="modal-footer"><button class="button button-secondary" type="button" data-action="close-modal">Cancel</button><button class="button button-primary" type="submit">Save changes</button></div></div></form></section></div>`;
    if (type === "details") return `<div class="modal-backdrop" data-action="backdrop-close"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><h2 id="modal-title">${esc(doc.name || "Document details")}</h2><p>Authorized document metadata</p></div>${close}</header><div class="modal-body">${state.modal.loading ? loadingMarkup(3) : state.modal.error ? alertMarkup(state.modal.error) : `<div class="form-grid"><div class="form-row"><label>Category</label><div>${esc(doc.category || "Uncategorized")}</div></div><div class="form-row"><label>Owner</label><div>${esc(doc.owner?.display_name || "—")}</div></div><div class="form-row"><label>File type</label><div>${esc(doc.content_type || "—")}</div></div><div class="form-row"><label>Size</label><div>${esc(fmtSize(doc.size))}</div></div><div class="form-row"><label>Added</label><div>${esc(fmtDate(doc.created_at, true))}</div></div><div class="form-row"><label>Access</label><div>${esc(doc.permission?.level ? humanize(doc.permission.level) : canManageDocument(doc) ? "Owner" : "Shared with you")}</div></div></div>`}<div class="modal-footer"><button class="button button-secondary" type="button" data-action="close-modal">Close</button><button class="button button-primary" data-action="download" data-id="${esc(doc.id)}">${icons.download} Download</button></div></div></section></div>`;
    if (type === "add-user") return `<div class="modal-backdrop" data-action="backdrop-close"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><header class="modal-header"><div><h2 id="modal-title">Add a workspace user</h2><p>Give a named colleague the access level they need.</p></div>${close}</header><form id="user-form"><div class="modal-body"><div id="modal-alert"></div><div class="form-row"><label for="user-name">Display name</label><input class="field" id="user-name" name="display_name" required autocomplete="name"></div><div class="form-row"><label for="user-username">Username</label><input class="field" id="user-username" name="username" required autocomplete="off"></div><div class="form-row"><label for="user-password">Temporary password</label><input class="field" id="user-password" name="password" type="password" required autocomplete="new-password"></div><div class="form-row"><label for="user-role">Role</label><select class="select" id="user-role" name="role" style="width:100%"><option value="viewer">Viewer — review shared files</option><option value="owner">Owner — manage own files</option><option value="administrator">Administrator — workspace management</option></select></div><div class="modal-footer"><button class="button button-secondary" type="button" data-action="close-modal">Cancel</button><button class="button button-primary" type="submit">Create user</button></div></div></form></section></div>`;
    return "";
  }

  function render() {
    if (!state.session) {
      app.innerHTML = loginMarkup();
      return;
    }
    app.innerHTML = `<div class="app-shell">${shellMarkup()}${modalMarkup()}</div>`;
    const root = document.getElementById("view-root");
    if (root) {
      const markup = state.view === "dashboard" ? dashboardMarkup()
        : state.view === "documents" ? documentsMarkup()
          : state.view === "permissions" ? permissionsMarkup()
            : state.view === "audit" ? auditMarkup()
              : state.view === "users" ? usersMarkup()
                : dashboardMarkup();
      root.innerHTML = markup;
    }
    if (state.modal) {
      window.requestAnimationFrame(() => {
        const target = app.querySelector('.modal input:not([type="file"]), .modal select, .modal [data-action="close-modal"]');
        target?.focus();
      });
    }
  }

  async function loadCurrentView(preserveError = false) {
    const sequence = ++state.loadSequence;
    state.loading = true;
    if (!preserveError) state.pageError = "";
    render();
    try {
      if (state.view === "dashboard") {
        state.dashboard = await getJSON("/api/dashboard");
      } else if (state.view === "documents") {
        const query = queryString(state.filters);
        state.documents = await getJSON(`/api/documents${query ? `?${query}` : ""}`);
      } else if (state.view === "permissions") {
        const query = await getJSON("/api/documents");
        state.documents = Array.isArray(query) ? query : [];
        const docs = state.documents.filter((doc) => canManageDocument(doc));
        if (!docs.some((doc) => String(doc.id) === String(state.selectedPermissionDoc))) {
          state.selectedPermissionDoc = docs[0] ? String(docs[0].id) : "";
        }
        if (state.selectedPermissionDoc) {
          const id = encodeURIComponent(state.selectedPermissionDoc);
          const [permissions, users] = await Promise.all([
            getJSON(`/api/documents/${id}/permissions`),
            getJSON("/api/users")
          ]);
          state.permissions = Array.isArray(permissions) ? permissions : [];
          state.permissionUsers = Array.isArray(users) ? users.filter((user) => user.active !== false) : [];
        } else {
          state.permissions = [];
          state.permissionUsers = [];
        }
      } else if (state.view === "audit") {
        const params = { limit: 100, ...state.auditFilters };
        const query = queryString(params);
        const logs = await getJSON(`/api/audit-logs${query ? `?${query}` : ""}`);
        state.auditLogs = Array.isArray(logs) ? logs : [];
      } else if (state.view === "users") {
        const users = await getJSON("/api/users");
        state.users = Array.isArray(users) ? users : [];
      }
    } catch (error) {
      if (error.status === 401) return;
      state.pageError = error.message || "Unable to load this view.";
    } finally {
      if (sequence === state.loadSequence) {
        state.loading = false;
        render();
      }
    }
  }

  function navigate(view) {
    const allowed = navItems().some(([key]) => key === view);
    if (!allowed) return;
    state.view = view;
    state.sidebarOpen = false;
    state.modal = null;
    render();
    loadCurrentView();
  }

  async function startSession() {
    try {
      const session = await getJSON("/api/session");
      if (!session?.user) {
        state.session = null;
        state.csrfToken = "";
        state.pageError = "";
        render();
        return;
      }
      state.session = session;
      state.csrfToken = session.csrf_token || "";
      state.view = "dashboard";
      state.pageError = "";
      render();
      loadCurrentView();
    } catch (error) {
      if (error.status === 401) {
        state.session = null;
        state.csrfToken = "";
        state.pageError = "";
        render();
      } else {
        app.innerHTML = `<div class="error-screen"><section class="error-card" role="alert"><div class="empty-visual">${icons.alert}</div><h1>TrustVault is unavailable</h1><p>${esc(error.message || "We could not establish a secure connection.")}</p><button class="button button-primary" data-action="retry-session">Try again</button></section></div>`;
      }
    }
  }

  async function refreshView() {
    state.modal = null;
    await loadCurrentView();
  }

  function showModalError(message) {
    const host = document.getElementById("modal-alert");
    if (host) host.innerHTML = alertMarkup(message);
  }

  async function downloadDocument(id) {
    try {
      const response = await fetch(apiPath(`/api/documents/${encodeURIComponent(id)}/download`), {
        credentials: "same-origin",
        headers: state.csrfToken ? { "X-CSRF-Token": state.csrfToken } : {}
      });
      if (response.status === 401) {
        handleUnauthorized();
        return;
      }
      if (!response.ok) {
        let message = `Download failed (${response.status}).`;
        try {
          const data = await response.json();
          if (data.detail || data.message) message = data.detail || data.message;
        } catch { /* The response may not be JSON. */ }
        if (response.status === 403) message = `Access denied: ${message}`;
        throw new RequestError(message, response.status);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i);
      const filename = match ? decodeURIComponent(match[1].replace(/"/g, "")) : "document";
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast("Download started.");
    } catch (error) {
      toast(error.message || "Unable to download this document.", "error");
    }
  }

  async function openDetails(id) {
    state.modal = { type: "details", document: state.documents.find((doc) => String(doc.id) === String(id)) || { id }, loading: true };
    render();
    try {
      const doc = await getJSON(`/api/documents/${encodeURIComponent(id)}`);
      state.modal = { type: "details", document: doc, loading: false };
    } catch (error) {
      if (error.status === 401) return;
      state.modal = { type: "details", document: state.modal?.document || { id }, loading: false, error: error.message };
    }
    render();
  }

  async function handleAction(action, element, clickEvent) {
    const id = element.dataset.id;
    const doc = state.documents.find((item) => String(item.id) === String(id));
    if (action === "logout") {
      try {
        await mutateJSON("/api/auth/logout", "POST");
      } catch (error) {
        if (error.status !== 401) {
          toast(error.message || "Unable to sign out.", "error");
          return;
        }
        return;
      }
      state.session = null;
      state.csrfToken = "";
      state.pageError = "";
      state.view = "login";
      render();
    } else if (action === "open-sidebar") {
      state.sidebarOpen = true;
      render();
    } else if (action === "close-sidebar") {
      state.sidebarOpen = false;
      render();
    } else if (action === "retry-session") {
      state.pageError = "";
      startSession();
    } else if (action === "retry-view") {
      loadCurrentView();
    } else if (action === "upload") {
      state.modal = { type: "upload" };
      render();
    } else if (action === "close-modal") {
      state.modal = null;
      render();
    } else if (action === "details") {
      openDetails(id);
    } else if (action === "download") {
      downloadDocument(id);
    } else if (action === "edit-document" && doc && canManageDocument(doc)) {
      state.modal = { type: "edit", document: doc };
      render();
    } else if (action === "delete-document" && doc && canManageDocument(doc)) {
      if (!window.confirm(`Delete “${doc.name}”? This cannot be undone.`)) return;
      try {
        await mutateJSON(`/api/documents/${encodeURIComponent(id)}`, "DELETE");
        if (String(state.selectedPermissionDoc) === String(id)) state.selectedPermissionDoc = "";
        toast("Document deleted.");
        await refreshView();
      } catch (error) {
        state.pageError = error.message;
        render();
      }
    } else if (action === "permissions-for" && doc && canManageDocument(doc)) {
      state.selectedPermissionDoc = String(id);
      navigate("permissions");
    } else if (action === "add-user") {
      state.modal = { type: "add-user" };
      render();
    } else if (action === "delete-user") {
      const name = element.dataset.name || "this user";
      if (!window.confirm(`Remove ${name} from the workspace? Their access will be revoked.`)) return;
      try {
        await mutateJSON(`/api/users/${encodeURIComponent(id)}`, "DELETE");
        toast("Workspace user removed.");
        await refreshView();
      } catch (error) {
        state.pageError = error.message;
        render();
      }
    } else if (action === "clear-doc-filters") {
      state.filters = { q: "", category: "", owner: "", from: "", to: "" };
      loadCurrentView();
    } else if (action === "clear-audit-filters") {
      state.auditFilters = { q: "", action: "" };
      loadCurrentView();
    } else if (action === "remove-permission") {
      if (!window.confirm("Remove this reviewer’s access to the document?")) return;
      const documentId = element.dataset.documentId;
      const userId = element.dataset.userId;
      try {
        await mutateJSON(`/api/documents/${encodeURIComponent(documentId)}/permissions/${encodeURIComponent(userId)}`, "DELETE");
        toast("Reviewer access removed.");
        await loadCurrentView();
      } catch (error) {
        state.pageError = error.message;
        render();
      }
    } else if (action === "backdrop-close" && element === clickEvent.target) {
      state.modal = null;
      render();
    }
  }

  async function submitLogin(form) {
    const formData = new FormData(form);
    const button = form.querySelector('button[type="submit"]');
    const previous = button.innerHTML;
    button.disabled = true;
    button.textContent = "Signing in…";
    const errorHost = document.getElementById("login-alert");
    if (errorHost) errorHost.innerHTML = "";
    try {
      const session = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: formData.get("username"), password: formData.get("password") }),
        headers: { "Content-Type": "application/json" }
      });
      if (!session?.user) throw new RequestError("Sign in succeeded, but no user session was returned.");
      state.session = session;
      state.csrfToken = session.csrf_token || "";
      state.pageError = "";
      state.view = "dashboard";
      render();
      loadCurrentView();
    } catch (error) {
      const alert = document.getElementById("login-alert");
      if (alert) alert.innerHTML = alertMarkup(error.message || "Unable to sign in.");
      const currentButton = form.querySelector('button[type="submit"]');
      if (currentButton) {
        currentButton.disabled = false;
        currentButton.innerHTML = previous;
      }
    }
  }

  async function submitUpload(form) {
    const formData = new FormData(form);
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = "Uploading…";
    try {
      await apiRequest("/api/documents", { method: "POST", body: formData });
      toast("Document uploaded.");
      state.modal = null;
      await loadCurrentView();
    } catch (error) {
      showModalError(error.message);
      const currentButton = form.querySelector('button[type="submit"]');
      if (currentButton) {
        currentButton.disabled = false;
        currentButton.innerHTML = `${icons.upload} Upload file`;
      }
    }
  }

  async function submitEdit(form) {
    const formData = new FormData(form);
    const id = form.dataset.id;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = "Saving…";
    try {
      await mutateJSON(`/api/documents/${encodeURIComponent(id)}`, "PATCH", {
        name: String(formData.get("name") || "").trim(),
        category: String(formData.get("category") || "").trim()
      });
      toast("Document details updated.");
      state.modal = null;
      await loadCurrentView();
    } catch (error) {
      showModalError(error.message);
      const currentButton = form.querySelector('button[type="submit"]');
      if (currentButton) {
        currentButton.disabled = false;
        currentButton.textContent = "Save changes";
      }
    }
  }

  async function submitUser(form) {
    const values = new FormData(form);
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = "Creating…";
    try {
      await mutateJSON("/api/users", "POST", {
        username: String(values.get("username") || "").trim(),
        display_name: String(values.get("display_name") || "").trim(),
        password: values.get("password"),
        role: values.get("role")
      });
      toast("Workspace user created.");
      state.modal = null;
      await loadCurrentView();
    } catch (error) {
      showModalError(error.message);
      const currentButton = form.querySelector('button[type="submit"]');
      if (currentButton) {
        currentButton.disabled = false;
        currentButton.textContent = "Create user";
      }
    }
  }

  async function submitPermission(form) {
    const formData = new FormData(form);
    const id = form.dataset.documentId;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await mutateJSON(`/api/documents/${encodeURIComponent(id)}/permissions`, "PUT", {
        user_id: formData.get("user_id"),
        level: formData.get("level")
      });
      toast("Reviewer access granted.");
      state.pageError = "";
      await loadCurrentView();
    } catch (error) {
      state.pageError = error.message;
      await loadCurrentView(true);
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function changePermission(select) {
    const docId = select.dataset.documentId;
    const userId = select.dataset.userId;
    const level = select.value;
    select.disabled = true;
    try {
      await mutateJSON(`/api/documents/${encodeURIComponent(docId)}/permissions`, "PUT", {
        user_id: userId,
        level
      });
      toast("Reviewer access updated.");
      state.pageError = "";
      await loadCurrentView();
    } catch (error) {
      state.pageError = error.message;
      await loadCurrentView(true);
    } finally {
      select.disabled = false;
    }
  }

  app.addEventListener("click", (event) => {
    const nav = event.target.closest("[data-nav]");
    if (nav) {
      navigate(nav.dataset.nav);
      return;
    }
    const actionEl = event.target.closest("[data-action]");
    if (actionEl) handleAction(actionEl.dataset.action, actionEl, event);
  });

  app.addEventListener("submit", (event) => {
    event.preventDefault();
    const form = event.target;
    if (form.id === "login-form") submitLogin(form);
    else if (form.id === "document-filters") {
      const data = new FormData(form);
      state.filters = { q: data.get("q") || "", category: data.get("category") || "", owner: data.get("owner") || "", from: data.get("from") || "", to: data.get("to") || "" };
      loadCurrentView();
    } else if (form.id === "audit-filters") {
      const data = new FormData(form);
      state.auditFilters = { q: data.get("q") || "", action: data.get("action") || "" };
      loadCurrentView();
    } else if (form.id === "upload-form") submitUpload(form);
    else if (form.id === "edit-form") submitEdit(form);
    else if (form.id === "user-form") submitUser(form);
    else if (form.id === "permission-add-form") submitPermission(form);
  });

  app.addEventListener("change", (event) => {
    const target = event.target;
    if (target.id === "permission-document") {
      state.selectedPermissionDoc = target.value;
      loadCurrentView();
    } else if (target.dataset.action === "change-permission") {
      changePermission(target);
    } else if (target.id === "upload-file") {
      const filename = target.files?.[0]?.name;
      const label = document.getElementById("upload-file-name");
      if (filename && label) label.textContent = filename;
      const name = document.getElementById("upload-name");
      if (filename && name && !name.value) name.value = filename.replace(/\.[^.]+$/, "");
    }
  });

  app.addEventListener("dragover", (event) => {
    const drop = event.target.closest(".upload-drop");
    if (drop) {
      event.preventDefault();
      drop.classList.add("dragover");
    }
  });
  app.addEventListener("dragleave", (event) => {
    const drop = event.target.closest(".upload-drop");
    if (drop) drop.classList.remove("dragover");
  });
  app.addEventListener("drop", (event) => {
    const drop = event.target.closest(".upload-drop");
    if (!drop) return;
    event.preventDefault();
    drop.classList.remove("dragover");
    const input = document.getElementById("upload-file");
    if (input && event.dataTransfer?.files?.length) {
      input.files = event.dataTransfer.files;
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      if (state.modal) {
        state.modal = null;
        render();
      } else if (state.sidebarOpen) {
        state.sidebarOpen = false;
        render();
      }
    }
  });

  render();
  startSession();
})();
