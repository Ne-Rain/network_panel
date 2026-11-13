"use strict";

const loginForm = document.getElementById("login-form");
const loginPanel = document.getElementById("login-panel");
const loginButton = document.getElementById("login-button");
const loginError = document.getElementById("login-error");
const loginStatus = document.getElementById("login-status");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const filesPanel = document.getElementById("files-panel");
const fileRows = document.getElementById("file-rows");
const fileCount = document.getElementById("file-count");
const accountLabel = document.getElementById("account-label");
const tableContainer = document.getElementById("table-container");
const fileTable = tableContainer.querySelector("table");
const visibleFileLimit = 10;
const emptyState = document.getElementById("empty-state");
const refreshButton = document.getElementById("refresh-button");
const uploadButton = document.getElementById("upload-button");
const uploadInput = document.getElementById("upload-input");
const filesStatus = document.getElementById("files-status");
const filesError = document.getElementById("files-error");
const taskUploadButton = document.getElementById("task-upload-button");
const fileLayout = document.getElementById("file-layout");
const uploadsPanel = document.getElementById("uploads-panel");
const downloadsPanel = document.getElementById("downloads-panel");
const filePageLinks = document.querySelectorAll("[data-file-page]");
const uploadTaskList = document.getElementById("upload-task-list");
const uploadsEmpty = document.getElementById("uploads-empty");
const uploadsActive = document.getElementById("uploads-active");
const uploadsFinished = document.getElementById("uploads-finished");
const uploadTasks = [];
let uploadFilter = "active";
let activeUploadTask = null;
const groupLabel = document.getElementById("group-label");
const loginLink = document.getElementById("login-link");
const fileNavigation = document.getElementById("file-navigation");
const backLink = document.getElementById("back-link");
const passwordToggle = document.getElementById("password-toggle");

const discoveryPanel = document.getElementById("discovery-panel");
const discoveryTitle = document.getElementById("discovery-title");
const discoveryStatus = document.getElementById("discovery-status");
const discoveryFingerprint = document.getElementById("discovery-fingerprint");
const discoveryRetry = document.getElementById("discovery-retry");
const discoveryTrust = document.getElementById("discovery-trust");

let serverReady = false;
let discoveryBusy = false;
let pendingFingerprint = "";

let account = null;
let pendingList = null;

const deleteDialog = document.getElementById("delete-dialog");
const deleteFileName = document.getElementById("delete-file-name");
const deleteError = document.getElementById("delete-error");
const deleteConfirm = document.getElementById("delete-confirm");
const deleteCancel = document.getElementById("delete-cancel");
const deleteClose = document.getElementById("delete-close");
const selectedFileIds = new Set();
let deleteTarget = null;
let deleting = false;

let displayedFiles = [];
let sortField = "name";
let sortAscending = true;
const sortButtons = tableContainer.querySelectorAll("[data-sort-field]");
const fileNameOrder = new Intl.Collator("zh-CN", { numeric: true });

const fileTypeLabels = new Map([
    ["file", "文档"],
    ["image", "图片"],
    ["video", "视频"],
    ["audio", "音频"],
    ["archive", "压缩文件"],
    ["other", "文件"]
]);

function formatFileSize(bytes) {
    if (bytes === null) {
        return "—";
    }

    const units = ["B", "KB", "MB", "GB", "TB"];
    let divisor = 1n;
    let unit = 0;
    while (unit < units.length - 1 && bytes >= divisor * 1000n) {
        divisor *= 1000n;
        unit++;
    }

    // Round to tenths without converting the byte count to a floating-point number.
    const tenths = (bytes * 10n + divisor / 2n) / divisor;
    return (tenths / 10n) + "." + (tenths % 10n) + " " + units[unit];
}

function formatUploadTime(uploadedAt) {
    if (typeof uploadedAt !== "string" || !/^\d{2}\/\d{2}\/\d{2} \d{2}[/:]\d{2}$/.test(uploadedAt)) {
        return null;
    }
    return uploadedAt.replace(/\/(\d{2})$/, ":$1");
}

function validateFile(file) {
    const id = file?.id;
    const name = file?.name;
    const validId = typeof id === "string" ? /^\d+$/.test(id) : Number.isSafeInteger(id) && id >= 0;

    if (!validId || typeof name !== "string" || !name.trim()) {
        throw new Error("文件列表格式不正确。");
    }

    const sizeBytes = file.size_bytes;
    return {
        id: String(id),
        name,
        bytes: typeof sizeBytes === "string" && /^\d{1,20}$/.test(sizeBytes) ? BigInt(sizeBytes) : null,
        type: fileTypeLabels.get(file.type) ?? "—",
        uploadedAt: formatUploadTime(file.uploadedAt)
    };
}

async function readListing(response) {
    let payload;
    try {
        payload = await response.json();
    } catch {
        throw new Error("文件列表格式不正确。");
    }

    if (!Array.isArray(payload?.files)) {
        throw new Error("文件列表格式不正确。");
    }

    const { username, group } = payload;
    const files = payload.files.map(validateFile);
    if (username === null && group === null) {
        return { account: null, files };
    }
    if (typeof username !== "string" || !username.trim() ||
        typeof group !== "string" || !group.trim()) {
        throw new Error("客户端接口返回的账号或组别无效。");
    }

    return { account: { username, group }, files };
}

function icon(name) {
    const namespace = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(namespace, "svg");
    const use = document.createElementNS(namespace, "use");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "#icon-" + name);
    svg.append(use);
    return svg;
}

function compareFiles(left, right) {
    const direction = sortAscending ? 1 : -1;
    if (sortField === "name") {
        return direction * fileNameOrder.compare(left.name, right.name);
    }

    const a = sortField === "id" ? BigInt(left.id) : left[sortField];
    const b = sortField === "id" ? BigInt(right.id) : right[sortField];
    if (a === b) {
        return 0;
    }
    if (a === null || b === null) {
        return a === null ? 1 : -1;
    }
    return direction * (a < b ? -1 : 1);
}

for (const button of sortButtons) {
    button.addEventListener("click", () => {
        const field = button.dataset.sortField;
        sortAscending = field !== sortField || !sortAscending;
        sortField = field;

        tableContainer.querySelector("[aria-sort]")?.removeAttribute("aria-sort");
        button.closest("th").setAttribute("aria-sort", sortAscending ? "ascending" : "descending");
        showFiles(displayedFiles);
    });
}

function updateFileListHeight() {
    const scrollable = fileRows.rows.length > visibleFileLimit;
    tableContainer.classList.toggle("has-scrollable-files", scrollable);
    if (!scrollable) {
        tableContainer.style.maxHeight = "";
        return;
    }

    const tableBounds = fileTable.getBoundingClientRect();
    if (tableBounds.height === 0) {
        return;
    }

    const lastVisibleRow = fileRows.rows[visibleFileLimit - 1].getBoundingClientRect();
    const bordersAndScrollbar = tableContainer.offsetHeight - tableContainer.clientHeight;
    tableContainer.style.maxHeight = (lastVisibleRow.bottom - tableBounds.top + bordersAndScrollbar) + "px";
}

const fileListResizeObserver = new ResizeObserver(updateFileListHeight);
fileListResizeObserver.observe(fileTable);
fileListResizeObserver.observe(tableContainer);

function selectFile(id) {
    selectedFileIds.clear();
    if (id !== null) selectedFileIds.add(id);
    for (const row of fileRows.rows) {
        const selected = selectedFileIds.has(row.dataset.fileId);
        row.querySelector(".file-checkbox").checked = selected;
        row.classList.toggle("is-selected", selected);
    }
}

function showFiles(files) {
    displayedFiles = files;
    const availableIds = new Set(files.map(file => file.id));
    for (const id of selectedFileIds) {
        if (!availableIds.has(id)) selectedFileIds.delete(id);
    }
    const rows = document.createDocumentFragment();
    for (const file of [...files].sort(compareFiles)) {
        const row = document.createElement("tr");
        row.dataset.fileId = file.id;
        row.tabIndex = 0;
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.className = "file-checkbox";
        checkbox.setAttribute("aria-label", "选择 " + file.name);
        checkbox.checked = selectedFileIds.has(file.id);
        row.classList.toggle("is-selected", checkbox.checked);
        const selectRow = () => selectFile(file.id);
        checkbox.addEventListener("change", () => {
            selectFile(checkbox.checked ? file.id : null);
        });
        row.addEventListener("click", event => {
            if (event.target.closest("input, a, button")) return;
            selectFile(selectedFileIds.has(file.id) ? null : file.id);
        });
        row.addEventListener("keydown", event => {
            if (event.target !== row || (event.key !== "Enter" && event.key !== " ")) return;
            event.preventDefault();
            selectFile(selectedFileIds.has(file.id) ? null : file.id);
        });
        const nameCell = row.insertCell();
        nameCell.className = "file-name";
        const nameContent = document.createElement("div");
        nameContent.className = "file-name-content";
        const badge = document.createElement("span");
        const archive = /\.(zip|7z|rar|tar|gz)$/i.test(file.name);
        const documentFile = /\.(pdf|docx?|pptx?|xlsx?)$/i.test(file.name);
        badge.className = archive ? "file-icon archive" : documentFile ? "file-icon document" : "file-icon";
        badge.append(icon(archive ? "archive" : "file"));
        const name = document.createElement("span");
        name.className = "file-display-name";
        name.textContent = file.name;
        nameContent.append(checkbox, badge, name);
        nameCell.append(nameContent);

        const idCell = row.insertCell();
        idCell.className = "file-id";
        idCell.textContent = file.id;
        for (const value of [formatFileSize(file.bytes), file.type, file.uploadedAt ?? "—"]) {
            const cell = row.insertCell();
            cell.className = "metadata";
            cell.textContent = value;
        }

        const download = document.createElement("a");
        download.className = "row-action download-action";
        download.href = "/api/files/" + encodeURIComponent(file.id);
        download.download = "";
        download.append(icon("download"));
        download.title = "下载";
        download.addEventListener("click", selectRow);
        download.setAttribute("aria-label", "下载 " + file.name);
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "row-action delete-action";
        remove.append(icon("delete"));
        remove.setAttribute("aria-label", "删除 " + file.name);
        remove.title = account ? "删除" : "登录后可删除本组文件";
        remove.disabled = !account || refreshButton.disabled;
        remove.addEventListener("click", () => {
            selectRow();
            openDeleteDialog(file);
        });
        const actions = document.createElement("div");
        actions.className = "row-actions";
        actions.append(download, remove);
        nameContent.append(actions);
        rows.append(row);
    }

    fileRows.replaceChildren(rows);
    fileCount.textContent = files.length + " 个文件";
    tableContainer.hidden = files.length === 0;
    emptyState.hidden = files.length !== 0;
    tableContainer.scrollTop = 0;
    updateFileListHeight();
}

function clearFiles() {
    displayedFiles = [];
    selectedFileIds.clear();
    fileRows.replaceChildren();
    updateFileListHeight();
    fileCount.textContent = "";
    tableContainer.hidden = true;
    emptyState.hidden = true;
}

function setAccount(identity) {
    if (account?.username !== identity?.username || account?.group !== identity?.group) {
        selectedFileIds.clear();
        clearUploadTasks();
    }
    account = identity;
    accountLabel.textContent = account?.username || "游客";
    accountLabel.title = accountLabel.textContent;
    groupLabel.hidden = !account;
    groupLabel.textContent = account?.group || "";
    groupLabel.title = groupLabel.textContent;
    loginLink.hidden = Boolean(account);
    uploadButton.disabled = refreshButton.disabled && Boolean(account) && !activeUploadTask;
    taskUploadButton.disabled = uploadButton.disabled;
    filesPanel.setAttribute("aria-label", account ? "本组文件与公共文件" : "公共文件");
    document.getElementById("empty-description").textContent = account
        ? "当前没有可下载的文件。" : "当前没有可下载的公共文件。";
}

function showPassword(visible) {
    passwordInput.type = visible ? "text" : "password";
    passwordToggle.setAttribute("aria-pressed", String(visible));
    document.getElementById("password-icon").setAttribute("href", visible ? "#icon-eye-off" : "#icon-eye");
}

function showView(focus = false) {
    const signingIn = serverReady && location.hash === "#login" && !account;
    const page = location.hash === "#uploads" ? "uploads"
        : location.hash === "#downloads" ? "downloads" : "home";
    const showFilesApp = serverReady && !signingIn;
    discoveryPanel.hidden = serverReady;
    loginPanel.hidden = !signingIn;
    backLink.hidden = !signingIn;
    fileNavigation.hidden = signingIn || !serverReady;
    fileLayout.hidden = !showFilesApp;
    filesPanel.hidden = !showFilesApp || page !== "home";
    uploadsPanel.hidden = !showFilesApp || page !== "uploads";
    downloadsPanel.hidden = !showFilesApp || page !== "downloads";
    for (const link of filePageLinks) {
        if (link.dataset.filePage === page) link.setAttribute("aria-current", "page");
        else link.removeAttribute("aria-current");
    }
    if (!signingIn && !loginButton.disabled) {
        passwordInput.value = "";
        showPassword(false);
        loginError.hidden = true;
    }
    if (focus) {
        const pagePanel = page === "uploads" ? uploadsPanel
            : page === "downloads" ? downloadsPanel : filesPanel;
        (serverReady ? (signingIn ? usernameInput : pagePanel) : discoveryTitle).focus();
    }
}

window.addEventListener("hashchange", () => {
    showView(true);
    if (!account && !filesPanel.hidden && !pendingList && tableContainer.hidden && emptyState.hidden) {
        loadFiles();
    }
});
passwordToggle.addEventListener("click", () => showPassword(passwordInput.type === "password"));

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!serverReady || loginButton.disabled) {
        return;
    }

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    loginError.hidden = true;
    if (!username || !password) {
        loginError.textContent = "请输入账号和密码。";
        loginError.hidden = false;
        (username ? passwordInput : usernameInput).focus();
        return;
    }

    loginButton.disabled = true;
    loginForm.setAttribute("aria-busy", "true");
    loginStatus.textContent = "正在验证账号…";
    loginStatus.hidden = false;

    try {
        let response;
        try {
            response = await fetch("/api/login", {
                method: "POST",
                body: new URLSearchParams({ username, password }),
                mode: "same-origin",
            });
        } catch {
            throw new Error("无法连接本地客户端。请确认客户端正在运行，再重试。");
        }

        if (response.status === 401) {
            passwordInput.value = "";
            passwordInput.focus();
            throw new Error("账号或密码错误，请重试。");
        }
        if (response.status === 400) {
            throw new Error("客户端未收到有效的账号或密码。");
        }
        if (response.status === 502 || response.status === 503 || response.status === 504) {
            throw new Error("本地客户端无法连接网盘服务端，请检查服务地址和证书。");
        }
        if (response.status !== 200) {
            throw new Error("登录失败（HTTP " + response.status + "）。");
        }

        const listing = await readListing(response);
        if (!listing.account) {
            throw new Error("登录响应缺少账号身份。");
        }
        pendingList?.abort();
        clearUploadTasks();
        setAccount(listing.account);
        loginForm.reset();
        showPassword(false);
        showFiles(listing.files);
        showFileMessage("列表已更新");
        history.replaceState(null, "", location.pathname + location.search);
        showView(true);
    } catch (error) {
        passwordInput.value = "";
        showPassword(false);
        loginError.textContent = error.message;
        loginError.hidden = false;
    } finally {
        loginStatus.hidden = true;
        loginForm.removeAttribute("aria-busy");
        loginButton.disabled = false;
    }
});

function showFileMessage(message, isError = false) {
    filesStatus.hidden = isError || !message;
    filesError.hidden = !isError || !message;
    (isError ? filesError : filesStatus).textContent = message;
}

function setFilesBusy(busy) {
    refreshButton.disabled = busy;
    uploadButton.disabled = busy && Boolean(account) && !activeUploadTask;
    taskUploadButton.disabled = uploadButton.disabled;
    for (const button of fileRows.querySelectorAll(".delete-action")) {
        button.disabled = busy || !account;
    }
    for (const button of sortButtons) button.disabled = busy;
}

function openDeleteDialog(file) {
    if (refreshButton.disabled || deleting) return;
    deleteTarget = file;
    deleteFileName.textContent = file.name;
    deleteError.hidden = true;
    deleteDialog.showModal();
    deleteCancel.focus();
}

function closeDeleteDialog() {
    if (!deleting) deleteDialog.close();
}

deleteCancel.addEventListener("click", closeDeleteDialog);
deleteClose.addEventListener("click", closeDeleteDialog);
deleteDialog.addEventListener("cancel", event => {
    if (deleting) event.preventDefault();
});
deleteDialog.addEventListener("close", () => {
    deleteTarget = null;
});

deleteConfirm.addEventListener("click", async () => {
    if (!deleteTarget || deleting) return;
    const target = deleteTarget;
    deleting = true;
    deleteError.hidden = true;
    deleteConfirm.disabled = true;
    deleteCancel.disabled = true;
    deleteClose.disabled = true;
    deleteConfirm.textContent = "正在删除…";
    pendingList?.abort();
    setFilesBusy(true);
    try {
        let response;
        try {
            response = await fetch("/api/files/" + encodeURIComponent(target.id), {
                method: "DELETE",
                mode: "same-origin"
            });
        } catch {
            throw new Error("删除连接中断，无法确认结果。请取消后刷新列表查看。");
        }
        if (response.status === 401) {
            deleteDialog.close();
            expireSession();
            return;
        }
        if (response.status === 404) {
            throw new Error("文件不存在或当前账号无权删除。");
        }
        if (response.status !== 204) {
            throw new Error("删除失败（HTTP " + response.status + "），请稍后重试。");
        }
        selectedFileIds.delete(target.id);
        deleteDialog.close();
        const confirmation = "已删除 " + target.name + "。";
        showFileMessage(confirmation + " 正在刷新列表…");
        try {
            if (await refreshFiles(confirmation + " ")) {
                showFileMessage(confirmation);
                filesPanel.focus();
            }
        } catch (error) {
            showFileMessage(confirmation + " " + error.message, true);
        }
    } catch (error) {
        deleteError.textContent = error.message;
        deleteError.hidden = false;
    } finally {
        deleting = false;
        deleteConfirm.disabled = false;
        deleteCancel.disabled = false;
        deleteClose.disabled = false;
        deleteConfirm.textContent = "确认删除";
        setFilesBusy(false);
    }
});

function expireSession(message = "") {
    setAccount(null);
    clearFiles();
    showFileMessage("");
    loginError.textContent = message + "登录会话已失效，请重新登录。";
    loginError.hidden = false;
    location.hash = "login";
}

async function refreshFiles(expiryMessage = "", startup = false) {
    const controller = new AbortController();
    pendingList = controller;
    try {
        let response;
        try {
            response = await fetch("/api/files", {
                cache: "no-store",
                mode: "same-origin",
                signal: controller.signal,
            });
        } catch {
            if (controller.signal.aborted) {
                return false;
            }
            throw new Error("无法连接本地客户端。");
        }

        if (controller.signal.aborted) {
            return false;
        }
        if (response.status === 401) {
            if (!startup && account) {
                expireSession(expiryMessage);
            } else {
                setAccount(null);
                clearFiles();
                showFileMessage("当前客户端需要登录才能读取文件列表。", true);
            }
            return false;
        }
        if (response.status !== 200) {
            throw new Error("刷新列表失败（HTTP " + response.status + "）。");
        }

        const listing = await readListing(response);
        if (controller.signal.aborted) {
            return false;
        }
        setAccount(listing.account);
        showFiles(listing.files);
        if (account && location.hash === "#login") {
            history.replaceState(null, "", location.pathname + location.search);
            showView();
        }
        return true;
    } catch (error) {
        if (controller.signal.aborted) {
            return false;
        }
        throw error;
    } finally {
        if (pendingList === controller) {
            pendingList = null;
        }
    }
}

async function loadFiles(startup = false) {
    setFilesBusy(true);
    showFileMessage(startup ? "正在加载文件…" : "正在刷新列表…");
    try {
        if (await refreshFiles("", startup)) {
            showFileMessage(startup ? "" : "列表已更新");
        }
    } catch (error) {
        showFileMessage(error.message, true);
    } finally {
        setFilesBusy(false);
    }
}

function showDiscovery(message, fingerprint = "") {
    serverReady = false;
    pendingFingerprint = fingerprint;
    setAccount(null);
    clearFiles();
    discoveryStatus.textContent = message;
    discoveryFingerprint.textContent = fingerprint;
    discoveryFingerprint.hidden = !fingerprint;
    discoveryTrust.hidden = !fingerprint;
    showView();
}

async function connectServer(confirm = false, startup = false) {
    if (discoveryBusy) {
        return;
    }

    discoveryBusy = true;
    discoveryRetry.disabled = true;
    discoveryTrust.disabled = true;
    setFilesBusy(true);
    if (serverReady) {
        showFileMessage("正在查找局域网中的服务器…");
    } else {
        discoveryStatus.textContent = confirm ? "正在确认服务器身份…" : "正在查找局域网中的服务器…";
    }

    try {
        const response = await fetch(confirm ? "/api/discover/trust" : "/api/discover", {
            method: "POST",
            mode: "same-origin",
            ...(confirm ? { body: pendingFingerprint } : {}),
        });
        if (response.status === 409) {
            showDiscovery("发现结果已变化，请重新查找服务器。");
            return;
        }
        if (!response.ok) {
            throw new Error("客户端无法完成服务器发现（HTTP " + response.status + "）。");
        }
        const result = await response.json();
        if (result.state === "missing") {
            showDiscovery("未找到服务器。请启动服务端并确认设备在同一局域网，再重新查找。");
            return;
        }
        if (result.state === "multiple") {
            showDiscovery("发现多台服务器。请只保留要连接的一台，再重新查找。");
            return;
        }
        if (result.state === "untrusted" && /^[0-9a-f]{64}$/.test(result.fingerprint)) {
            showDiscovery("发现 " + result.name + "（" + result.host + ":" + result.port +
                "）。请与服务端本机输出的 SHA-256 指纹核对。", result.fingerprint);
            return;
        }
        if (result.state !== "ready") {
            throw new Error("客户端返回了无效的发现结果。");
        }

        serverReady = true;
        pendingFingerprint = "";
        showView();
        await loadFiles(startup);
    } catch (error) {
        showDiscovery(error.message || "无法连接本地客户端，请重试。");
    } finally {
        discoveryBusy = false;
        discoveryRetry.disabled = false;
        discoveryTrust.disabled = false;
        setFilesBusy(false);
        pumpUploadQueue();
    }
}

discoveryRetry.addEventListener("click", () => connectServer());
discoveryTrust.addEventListener("click", () => connectServer(true));
refreshButton.addEventListener("click", () => connectServer());
function chooseUpload() {
    if (account) {
        uploadInput.click();
    } else {
        location.hash = "login";
    }
}
uploadButton.addEventListener("click", chooseUpload);
taskUploadButton.addEventListener("click", chooseUpload);

function clearUploadTasks() {
    for (const task of uploadTasks) {
        task.discarded = true;
        clearTimeout(task.pollTimer);
        task.pollController?.abort();
        task.cancelController?.abort();
        task.request?.abort();
        task.file = null;
    }
    uploadTasks.length = 0;
    if (activeUploadTask) {
        activeUploadTask = null;
        setFilesBusy(discoveryBusy || deleting);
    }
    renderUploadTasks();
}

function renderUploadTasks() {
    const active = uploadTasks.filter(task => !task.finished).length;
    const finished = uploadTasks.length - active;
    document.getElementById("uploads-active-count").textContent = active;
    document.getElementById("uploads-finished-count").textContent = finished;
    const badge = document.getElementById("upload-nav-count");
    badge.textContent = active;
    badge.hidden = active === 0;
    uploadsActive.setAttribute("aria-pressed", String(uploadFilter === "active"));
    uploadsFinished.setAttribute("aria-pressed", String(uploadFilter === "finished"));
    document.getElementById("upload-summary").textContent = uploadFilter === "active"
        ? (active ? active + " 个上传任务正在进行" : "暂无进行中的上传任务")
        : finished + " 个已结束的上传任务";
    const visibleTasks = uploadTasks.filter(task => task.finished === (uploadFilter === "finished"));
    uploadsEmpty.hidden = visibleTasks.length !== 0;
    const rows = document.createDocumentFragment();
    const labels = {
        queued: "等待上传",
        preparing: "正在准备上传",
        running: "正在上传",
        confirming: "正在等待服务器确认",
        success: "上传成功",
        failed: "上传失败",
        unknown: "结果待确认"
    };
    for (const task of uploadFilter === "active" ? visibleTasks : [...visibleTasks].reverse()) {
        const row = document.createElement("article");
        row.className = "upload-task";
        row.dataset.state = task.state;
        row.setAttribute("role", "listitem");
        const nameGroup = document.createElement("div");
        nameGroup.className = "task-name-group";
        const badge = document.createElement("span");
        badge.className = "file-icon";
        badge.append(icon("file"));
        const nameText = document.createElement("div");
        nameText.className = "task-name-text";
        const name = document.createElement("p");
        name.className = "task-name";
        name.textContent = task.name;
        name.title = task.name;
        const message = document.createElement("p");
        message.className = "task-message";
        message.textContent = task.cancelling ? "正在请求取消…"
            : task.message || task.cancelNotice || task.notice || labels[task.state];
        nameText.append(name, message);
        nameGroup.append(badge, nameText);
        const progressGroup = document.createElement("div");
        progressGroup.className = "task-progress-group";
        const progress = document.createElement("progress");
        progress.className = "task-progress";
        progress.max = 1000;
        progress.setAttribute("aria-label", task.name + " 上传进度");
        const percent = task.total > 0n
            ? Number(task.sent * 1000n / task.total) : task.state === "success" ? 1000 : 0;
        if (task.state !== "preparing") progress.value = Math.min(percent, 1000);
        const bytes = document.createElement("p");
        bytes.className = "task-bytes";
        bytes.textContent = formatFileSize(task.sent) + " / " + formatFileSize(task.total)
            + " · " + (Math.min(percent, 1000) / 10).toFixed(1) + "%";
        progressGroup.append(progress, bytes);
        const speed = document.createElement("p");
        speed.className = "task-speed";
        speed.textContent = task.state === "running"
            ? formatFileSize(BigInt(Math.max(0, Math.round(task.speed)))) + "/s" : "—";
        const elapsed = task.startedAt
            ? Math.max(0, Math.floor(((task.endedAt || Date.now()) - task.startedAt) / 1000)) : 0;
        const time = document.createElement("p");
        time.className = "task-time";
        time.title = "已用时间";
        time.textContent = [Math.floor(elapsed / 3600), Math.floor(elapsed / 60) % 60, elapsed % 60]
            .map(value => String(value).padStart(2, "0")).join(":");
        row.append(nameGroup, progressGroup, speed, time);
        if (!task.finished) {
            const cancel = document.createElement("button");
            cancel.type = "button";
            cancel.className = "text-action task-cancel";
            cancel.textContent = task.cancelling ? "取消中…" : "取消";
            cancel.setAttribute("aria-label", "取消上传 " + task.name);
            cancel.disabled = task.state !== "queued" && (task.cancelling || !task.id || task.total === 0n
                || task.cancelBlocked || !["preparing", "running"].includes(task.state));
            cancel.title = cancel.disabled && !task.cancelling
                ? "仅可取消已创建且尚未进入确认阶段的非空上传" : "取消此上传";
            cancel.addEventListener("click", () => cancelUploadTask(task));
            row.append(cancel);
        }
        rows.append(row);
    }
    uploadTaskList.replaceChildren(rows);
}

async function cancelUploadTask(task) {
    if (task.state === "queued" && !task.discarded) {
        task.discarded = true;
        task.file = null;
        const index = uploadTasks.indexOf(task);
        if (index !== -1) uploadTasks.splice(index, 1);
        renderUploadTasks();
        return;
    }
    if (task.cancelling || task.finished || task.discarded || !task.id ||
        task.total === 0n || task.cancelBlocked ||
        !["preparing", "running"].includes(task.state)) return;
    task.cancelling = true;
    task.cancelNotice = "";
    const cancelController = new AbortController();
    task.cancelController = cancelController;
    const cancelTimeout = setTimeout(() => cancelController.abort(), 10000);
    task.cancelPromise = (async () => {
        try {
            const response = await fetch("/api/task/" + encodeURIComponent(task.id), {
                method: "DELETE",
                mode: "same-origin",
                signal: cancelController.signal
            });
            if (task.discarded) return;
            if (response.status === 204) {
                task.discarded = true;
                clearTimeout(task.pollTimer);
                task.pollController?.abort();
                task.request?.abort();
                const index = uploadTasks.indexOf(task);
                if (index !== -1) uploadTasks.splice(index, 1);
                showFileMessage("已取消上传 " + task.name + "。");
            } else if (response.status === 409) {
                task.cancelBlocked = true;
                task.cancelNotice = "任务已进入不可取消阶段，正在等待上传结果。";
            } else if (response.status === 401) {
                expireSession();
            } else {
                task.cancelNotice = "取消未成功（HTTP " + response.status + "），上传结果仍以原请求为准。";
            }
        } catch {
            if (!task.discarded) {
                task.cancelNotice = "无法确认取消结果，请重试取消或等待上传结果。";
            }
        } finally {
            clearTimeout(cancelTimeout);
            task.cancelling = false;
            if (!task.discarded) renderUploadTasks();
        }
    })();
    renderUploadTasks();
    await task.cancelPromise;
    renderUploadTasks();
}

uploadsActive.addEventListener("click", () => {
    uploadFilter = "active";
    renderUploadTasks();
});
uploadsFinished.addEventListener("click", () => {
    uploadFilter = "finished";
    renderUploadTasks();
});

function finishUploadTask(task, state, message) {
    task.state = state;
    task.message = message;
    task.finished = true;
    task.endedAt = Date.now();
    clearTimeout(task.pollTimer);
    task.pollController?.abort();
    task.request = null;
    if (!task.discarded) {
        uploadFilter = uploadTasks.some(item => item.state === "queued" && !item.discarded)
            ? "active" : "finished";
        renderUploadTasks();
    }
}

async function pollUploadTask(task) {
    if (task.finished || task.discarded) return;
    const controller = new AbortController();
    task.pollController = controller;
    try {
        const response = await fetch("/api/task/" + encodeURIComponent(task.id), {
            cache: "no-store",
            mode: "same-origin",
            signal: controller.signal
        });
        if (response.status !== 200) throw new Error("进度暂时不可用，上传仍在继续。");
        const snapshot = await response.json();
        const validBytes = value => typeof value === "string" && /^\d{1,20}$/.test(value);
        if (snapshot?.task_id !== task.id || !validBytes(snapshot.sent_bytes) ||
            !validBytes(snapshot.total_bytes) ||
            !["restart", "running", "confirming", "success", "failed"].includes(snapshot.state)) {
            throw new Error("进度数据暂时不可用，上传仍在继续。");
        }
        if (task.finished || task.discarded) return;
        const sent = BigInt(snapshot.sent_bytes);
        const total = BigInt(snapshot.total_bytes);
        if (sent > total) throw new Error("进度数据暂时不可用，上传仍在继续。");
        const now = performance.now();
        task.speed = Number(sent - task.sent) * 1000 / Math.max(1, now - task.sampledAt);
        task.sampledAt = now;
        task.sent = sent;
        if (snapshot.state !== "restart") task.total = total;
        task.state = snapshot.state === "restart" ? "preparing"
            : snapshot.state === "running" ? "running" : "confirming";
        task.notice = snapshot.state === "failed" ? "服务器报告失败，正在获取请求结果。" : "";
    } catch (error) {
        if (controller.signal.aborted || task.finished || task.discarded) return;
        task.notice = error.message || "暂时无法读取进度，上传仍在继续。";
    } finally {
        if (!task.finished && !task.discarded) {
            renderUploadTasks();
            task.pollTimer = setTimeout(() => pollUploadTask(task), 400);
        }
    }
}

function sendFile(file, task) {
    return new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();
        task.request = request;
        const query = new URLSearchParams({ name: file.name, task_id: task.id });
        request.open("POST", "/api/files?" + query);
        request.setRequestHeader("Content-Type", "application/octet-stream");
        request.addEventListener("load", () => resolve(request));
        request.addEventListener("error", () => reject(new Error("上传连接中断，无法确认结果。请刷新列表查看文件是否已上传。")));
        request.addEventListener("abort", () => reject(new Error("上传连接已结束，无法确认结果。")));
        request.send(file);
    });
}

function readUploadId(responseText) {
    try {
        const id = JSON.parse(responseText)?.id;
        return typeof id === "string" && /^\d+$/.test(id) ? id : "";
    } catch {
        return "";
    }
}

uploadInput.addEventListener("change", () => {
    const files = Array.from(uploadInput.files);
    uploadInput.value = "";
    if (!files.length || !account || !serverReady || discoveryBusy || deleting) return;
    for (const file of files) {

    const task = {
        name: file.name,
        file,
        id: "",
        total: BigInt(file.size),
        sent: 0n,
        speed: 0,
        sampledAt: performance.now(),
        startedAt: 0,
        state: "queued",
        finished: false,
        discarded: false,
        message: "",
        notice: ""
    };
    uploadTasks.push(task);
    }
    uploadFilter = "active";
    renderUploadTasks();
    location.hash = "uploads";
    pumpUploadQueue();
});

function pumpUploadQueue() {
    if (activeUploadTask || !account || !serverReady || discoveryBusy || deleting) return;
    const task = uploadTasks.find(item => item.state === "queued" && !item.discarded);
    if (!task) return;
    activeUploadTask = task;
    task.state = "preparing";
    task.startedAt = Date.now();
    task.sampledAt = performance.now();
    void runUploadTask(task);
}

async function runUploadTask(task) {
    const file = task.file;
    setFilesBusy(true);
    renderUploadTasks();
    showFileMessage("正在上传 " + file.name + "…");
    let failureState = "failed";

    try {
        const created = await fetch("/api/task/", {
            method: "POST",
            mode: "same-origin"
        });
        if (task.discarded) return;
        if (created.status === 401) {
            expireSession();
            return;
        }
        if (created.status !== 200) {
            throw new Error("创建上传任务失败（HTTP " + created.status + "）。");
        }
        task.id = (await created.text()).trim();
        if (task.discarded) return;
        if (!/^[0-9a-f]{64}$/.test(task.id)) {
            throw new Error("客户端返回的上传任务编号无效。");
        }
        pollUploadTask(task);
        failureState = "unknown";
        const response = await sendFile(file, task);
        await task.cancelPromise;
        if (task.discarded) return;
        failureState = "failed";
        if (response.status === 401) {
            expireSession();
            return;
        }
        if (response.status !== 201) {
            const message = response.status === 400
                ? "上传请求被拒绝，请检查文件名。"
                : "无法确认上传结果（HTTP " + response.status + "）。请刷新列表查看文件是否已上传。";
            throw new Error(message);
        }

        const id = readUploadId(response.responseText);
        const confirmation = id ? "上传成功，文件编号 " + id + "。" : "服务端已确认上传。";
        task.sent = task.total;
        finishUploadTask(task, "success", confirmation);
        showFileMessage(confirmation + " 正在刷新列表…");
        try {
            if (await refreshFiles(confirmation + " ")) {
                showFileMessage(confirmation + " 文件列表已更新。");
            }
        } catch (error) {
            showFileMessage(confirmation + " " + error.message, true);
        }
    } catch (error) {
        await task.cancelPromise;
        if (task.discarded) return;
        const message = error.message || "上传失败，请稍后重试。";
        finishUploadTask(task, failureState, message);
        showFileMessage(message, true);
    } finally {
        task.request = null;
        task.file = null;
        if (activeUploadTask === task) {
            activeUploadTask = null;
            pumpUploadQueue();
            setFilesBusy(Boolean(activeUploadTask) || discoveryBusy || deleting);
        }
    }
}

renderUploadTasks();
showView(location.hash === "#login");
connectServer(false, true);
