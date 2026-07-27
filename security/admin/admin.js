const blacklistBody =
    document.getElementById("blacklistBody");

const blacklistCount =
    document.getElementById("blacklistCount");

const messageBox =
    document.getElementById("messageBox");

const addIpForm =
    document.getElementById("addIpForm");

const ipInput =
    document.getElementById("ipInput");

const reasonInput =
    document.getElementById("reasonInput");

const refreshButton =
    document.getElementById("refreshButton");


function showMessage(message, type = "success") {
    messageBox.textContent = message;

    messageBox.className = `message ${type}`;

    window.setTimeout(() => {
        messageBox.className = "message hidden";
    }, 5000);
}


function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


async function loadBlacklist() {
    blacklistBody.innerHTML = `
        <tr>
            <td colspan="4" class="empty-cell">
                Loading blacklist...
            </td>
        </tr>
    `;

    try {
        const response = await fetch("/api/blacklist");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Could not load blacklist"
            );
        }

        renderBlacklist(result.blacklist);

    } catch (error) {
        blacklistBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-cell error-text">
                    ${escapeHtml(error.message)}
                </td>
            </tr>
        `;

        showMessage(error.message, "error");
    }
}


function renderBlacklist(blacklist) {
    blacklistCount.textContent =
        `${blacklist.length} IP${blacklist.length === 1 ? "" : "s"}`;

    if (blacklist.length === 0) {
        blacklistBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-cell">
                    No IP addresses are currently blacklisted.
                </td>
            </tr>
        `;

        return;
    }

    blacklistBody.innerHTML = blacklist
        .map((entry) => {
            const ip = escapeHtml(entry.ip);
            const reason = escapeHtml(
                entry.reason || "No reason supplied"
            );

            return `
                <tr>
                    <td>
                        <code>${ip}</code>
                    </td>

                    <td>${reason}</td>

                    <td>
                        <span class="status blacklisted">
                            Blacklisted
                        </span>
                    </td>

                    <td>
                        <button
                            class="allow-button"
                            type="button"
                            data-ip="${ip}"
                        >
                            Remove and allow
                        </button>
                    </td>
                </tr>
            `;
        })
        .join("");

    document
        .querySelectorAll(".allow-button")
        .forEach((button) => {
            button.addEventListener("click", () => {
                removeFromBlacklist(button.dataset.ip);
            });
        });
}


async function removeFromBlacklist(ip) {
    const confirmed = window.confirm(
        `Remove ${ip} from the blacklist and allow it to access the Asset?`
    );

    if (!confirmed) {
        return;
    }

    try {
        const response = await fetch(
            "/api/blacklist/remove",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({ ip })
            }
        );

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Could not remove IP"
            );
        }

        showMessage(result.message, "success");
        await loadBlacklist();

    } catch (error) {
        showMessage(error.message, "error");
    }
}


addIpForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const ip = ipInput.value.trim();

    const reason =
        reasonInput.value.trim() ||
        "Added manually by administrator";

    if (!ip) {
        showMessage("Enter an IP address", "error");
        return;
    }

    try {
        const response = await fetch(
            "/api/blacklist/add",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    ip,
                    reason
                })
            }
        );

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message ||
                "Could not add IP to blacklist"
            );
        }

        showMessage(result.message, "success");

        addIpForm.reset();

        await loadBlacklist();

    } catch (error) {
        showMessage(error.message, "error");
    }
});


refreshButton.addEventListener(
    "click",
    loadBlacklist
);


loadBlacklist();