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

function validateFile(file) {
    const id = file?.id;
    const name = file?.name;
    const validId = typeof id === "string" ? /^\d+$/.test(id) : Number.isSafeInteger(id) && id >= 0;

    if (!validId || typeof name !== "string" || !name.trim()) {
        throw new Error("文件列表格式不正确。");
    }

    return { id: String(id), name };
}

async function readFiles(response) {
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
        return files.map(validateFile);
    }

    if (contentType && contentType !== "text/plain") {
        throw new Error("客户端接口返回了不支持的内容。");
    }

    const text = (await response.text()).trim();
    if (!text) {
        return [];
    }

    const fields = text.split(/\s+/);
    if (fields.length % 2 !== 0) {
        throw new Error("文件列表格式不正确。");
    }

    const files = [];
    for (let index = 0; index < fields.length; index += 2) {
        files.push(validateFile({ id: fields[index], name: fields[index + 1] }));
    }
    return files;
}

function showFiles(files, username) {
    const rows = document.createDocumentFragment();
    for (const file of files) {
        const row = document.createElement("tr");
        const idCell = document.createElement("td");
        const nameCell = document.createElement("td");
        idCell.textContent = file.id;
        nameCell.textContent = file.name;
        row.append(idCell, nameCell);
        rows.append(row);
    }

    fileRows.replaceChildren(rows);
    fileCount.textContent = files.length + " 个文件";
    accountLabel.textContent = "当前账号：" + username;
    tableContainer.hidden = files.length === 0;
    emptyState.hidden = files.length !== 0;
    loginPanel.hidden = true;
    filesPanel.hidden = false;
    document.getElementById("files-title").focus();
}

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

        const files = await readFiles(response);
        loginForm.reset();
        showFiles(files, username);
    } catch (error) {
        loginError.textContent = error.message;
        loginError.hidden = false;
    } finally {
        loginStatus.hidden = true;
        loginForm.removeAttribute("aria-busy");
        loginButton.disabled = false;
    }
});
