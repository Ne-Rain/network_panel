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
const emptyState = document.getElementById("empty-state");
const refreshButton = document.getElementById("refresh-button");
const uploadButton = document.getElementById("upload-button");
const uploadInput = document.getElementById("upload-input");
const filesStatus = document.getElementById("files-status");
const filesError = document.getElementById("files-error");
const uploadProgress = document.getElementById("upload-progress");
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

function validateFile(file) {
    const id = file?.id;
    const name = file?.name;
    const validId = typeof id === "string" ? /^\d+$/.test(id) : Number.isSafeInteger(id) && id >= 0;

    if (!validId || typeof name !== "string" || !name.trim()) {
        throw new Error("文件列表格式不正确。");
    }

    return { id: String(id), name };
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

function showFiles(files) {
    const rows = document.createDocumentFragment();
    for (const file of files) {
        const row = document.createElement("tr");
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
        name.textContent = file.name;
        nameContent.append(badge, name);
        nameCell.append(nameContent);

        const idCell = row.insertCell();
        idCell.className = "file-id";
        idCell.textContent = file.id;
        for (let column = 0; column < 3; column++) {
            const cell = row.insertCell();
            cell.className = "metadata";
            cell.textContent = "—";
        }

        const download = document.createElement("a");
        download.className = "text-action download-action";
        download.href = "/api/files/" + encodeURIComponent(file.id);
        download.download = "";
        download.append(icon("download"), "下载");
        download.setAttribute("aria-label", "下载 " + file.name);
        row.insertCell().append(download);
        rows.append(row);
    }

    fileRows.replaceChildren(rows);
    fileCount.textContent = files.length + " 个文件";
    tableContainer.hidden = files.length === 0;
    emptyState.hidden = files.length !== 0;
}

function clearFiles() {
    fileRows.replaceChildren();
    fileCount.textContent = "";
    tableContainer.hidden = true;
    emptyState.hidden = true;
}

function setAccount(identity) {
    account = identity;
    accountLabel.textContent = account?.username || "游客";
    accountLabel.title = accountLabel.textContent;
    groupLabel.hidden = !account;
    groupLabel.textContent = account?.group || "";
    groupLabel.title = groupLabel.textContent;
    loginLink.hidden = Boolean(account);
    uploadButton.disabled = refreshButton.disabled && Boolean(account);
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
    discoveryPanel.hidden = serverReady;
    loginPanel.hidden = !signingIn;
    backLink.hidden = !signingIn;
    fileNavigation.hidden = signingIn || !serverReady;
    filesPanel.hidden = signingIn || !serverReady;
    if (!signingIn && !loginButton.disabled) {
        passwordInput.value = "";
        showPassword(false);
        loginError.hidden = true;
    }
    if (focus) {
        (serverReady ? (signingIn ? usernameInput : filesPanel) : discoveryTitle).focus();
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
    uploadButton.disabled = busy && Boolean(account);
}

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
    }
}

discoveryRetry.addEventListener("click", () => connectServer());
discoveryTrust.addEventListener("click", () => connectServer(true));
refreshButton.addEventListener("click", () => connectServer());
uploadButton.addEventListener("click", () => {
    if (account) {
        uploadInput.click();
    } else {
        location.hash = "login";
    }
});

function sendFile(file) {
    return new Promise((resolve, reject) => {
        const request = new XMLHttpRequest();
        const query = new URLSearchParams({ name: file.name });
        request.open("POST", "/api/files?" + query);
        request.setRequestHeader("Content-Type", "application/octet-stream");
        request.upload.addEventListener("progress", (event) => {
            if (event.lengthComputable && event.total > 0) {
                uploadProgress.max = event.total;
                uploadProgress.value = event.loaded;
            }
        });
        request.upload.addEventListener("load", () => {
            uploadProgress.removeAttribute("value");
            showFileMessage("文件已发送，等待网盘服务端确认…");
        });
        request.addEventListener("load", () => resolve(request));
        request.addEventListener("error", () => reject(new Error("上传连接中断，无法确认结果。请刷新列表查看文件是否已上传。")));
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

uploadInput.addEventListener("change", async () => {
    const file = uploadInput.files[0];
    uploadInput.value = "";
    if (!file || !account || uploadButton.disabled) {
        return;
    }

    setFilesBusy(true);
    showFileMessage("正在上传 " + file.name + "…");
    uploadProgress.removeAttribute("value");
    uploadProgress.hidden = false;

    try {
        const response = await sendFile(file);
        uploadProgress.hidden = true;
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
        showFileMessage(confirmation + " 正在刷新列表…");
        try {
            if (await refreshFiles(confirmation + " ")) {
                showFileMessage(confirmation + " 文件列表已更新。");
            }
        } catch (error) {
            showFileMessage(confirmation + " " + error.message, true);
        }
    } catch (error) {
        showFileMessage(error.message, true);
    } finally {
        uploadProgress.hidden = true;
        setFilesBusy(false);
    }
});

showView(location.hash === "#login");
connectServer(false, true);
