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
const filesTitle = document.getElementById("files-title");
const groupLabel = document.getElementById("group-label");
const loginLink = document.getElementById("login-link");
const fileNavigation = document.getElementById("file-navigation");
const backLink = document.getElementById("back-link");
const passwordToggle = document.getElementById("password-toggle");
const accountKey = "netpanel.account";

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
    const contentType = (response.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();

    if (contentType === "application/json" || contentType.endsWith("+json")) {
        let payload;
        try {
            payload = await response.json();
        } catch {
            throw new Error("文件列表格式不正确。");
        }
        const files = Array.isArray(payload) ? payload : payload?.files;
        if (!Array.isArray(files)) {
            throw new Error("文件列表格式不正确。");
        }
        return {
            files: files.map(validateFile),
            username: typeof payload.username === "string" ? payload.username.trim() : "",
            group: typeof payload.group === "string" ? payload.group.trim() : "",
        };
    }

    if (contentType && contentType !== "text/plain") {
        throw new Error("客户端接口返回了不支持的内容。");
    }

    const text = (await response.text()).trim();
    if (!text) {
        return { files: [] };
    }

    const fields = text.split(/\s+/);
    if (fields.length % 2 !== 0) {
        throw new Error("文件列表格式不正确。");
    }

    const files = [];
    for (let index = 0; index < fields.length; index += 2) {
        files.push(validateFile({ id: fields[index], name: fields[index + 1] }));
    }
    return { files };
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
        download.className = "text-action";
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

function rememberedAccount() {
    try {
        const saved = JSON.parse(sessionStorage.getItem(accountKey));
        if (typeof saved?.username === "string" && saved.username) {
            return { username: saved.username, group: typeof saved.group === "string" ? saved.group : "" };
        }
    } catch {
        // The session cookie still controls API access if browser storage is unavailable.
    }
    return null;
}

function setAccount(identity) {
    account = identity;
    try {
        if (account) {
            sessionStorage.setItem(accountKey, JSON.stringify(account));
        } else {
            sessionStorage.removeItem(accountKey);
        }
    } catch {
        // In-memory identity remains available for the current page.
    }

    accountLabel.textContent = account?.username || "游客";
    accountLabel.title = accountLabel.textContent;
    groupLabel.hidden = !account;
    groupLabel.textContent = account ? account.group || "组别 —" : "";
    groupLabel.title = groupLabel.textContent;
    loginLink.hidden = Boolean(account);
    uploadButton.disabled = refreshButton.disabled && Boolean(account);
    filesTitle.textContent = account ? "文件" : "公共文件";
    document.getElementById("file-banner").classList.toggle("is-member", Boolean(account));
    document.getElementById("files-description").textContent = account ? "本组文件与公共文件" : "直接浏览和下载公共文件";
    document.getElementById("empty-description").textContent = account
        ? "当前没有可下载的文件。" : "当前没有可下载的公共文件。";
}

function showPassword(visible) {
    passwordInput.type = visible ? "text" : "password";
    passwordToggle.setAttribute("aria-pressed", String(visible));
    document.getElementById("password-icon").setAttribute("href", visible ? "#icon-eye-off" : "#icon-eye");
}

function showView(focus = false) {
    const signingIn = location.hash === "#login" && !account;
    loginPanel.hidden = !signingIn;
    backLink.hidden = !signingIn;
    fileNavigation.hidden = signingIn;
    filesPanel.hidden = signingIn;
    if (!signingIn && !loginButton.disabled) {
        passwordInput.value = "";
        showPassword(false);
        loginError.hidden = true;
    }
    if (focus) {
        (signingIn ? usernameInput : filesTitle).focus();
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
    if (loginButton.disabled) {
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
        pendingList?.abort();
        setAccount({ username: listing.username || username, group: listing.group || "" });
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
        const previous = startup ? rememberedAccount() : account;
        const username = listing.username || previous?.username;
        if (username) {
            const group = listing.group || (previous?.username === username ? previous.group : "");
            setAccount({ username, group });
        }
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
        pendingList = null;
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

refreshButton.addEventListener("click", () => loadFiles());
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
loadFiles(true);