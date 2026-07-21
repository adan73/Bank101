function showMessage(element, message, type = "danger") {
    element.textContent = message;
    element.className = `alert alert-${type}`;
    element.hidden = false;
}

function formatMoney(value) {
    return new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD"
    }).format(Number(value || 0));
}

function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value == null ? "" : String(value);
    return div.innerHTML;
}

function renderTransactions(transactions) {
    const body = document.getElementById("transactions-body");
    if (!transactions.length) {
        body.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No transactions yet</td></tr>';
        return;
    }

    body.innerHTML = transactions.map(transaction => {
        const direction = transaction.type === "Received" ? "From" : "To";
        const sign = transaction.type === "Received" ? "+" : "-";
        return `
            <tr>
                <td>
                    ${direction}: ${escapeHtml(transaction.recipient)}
                    ${transaction.description ? `<div class="small text-muted">${escapeHtml(transaction.description)}</div>` : ""}
                </td>
                <td>${sign}${formatMoney(transaction.amount)}</td>
                <td><span class="badge bg-success">${escapeHtml(transaction.status)}</span></td>
            </tr>`;
    }).join("");
}

async function loadDashboard() {
    const messageBox = document.getElementById("dashboard-message");
    try {
        const response = await fetch("/api/dashboard");
        if (response.status === 401) {
            window.location.href = "/";
            return;
        }
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Could not load account data");

        document.getElementById("balance-value").textContent = formatMoney(data.user.balance);
        renderTransactions(data.transactions);
    } catch (error) {
        showMessage(messageBox, error.message);
    }
}

async function submitTransfer(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const messageBox = document.getElementById("dashboard-message");
    const button = form.querySelector("button[type='submit']");

    messageBox.hidden = true;
    button.disabled = true;
    button.textContent = "Transferring...";

    try {
        const response = await fetch("/api/transfer", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                recipient: form.recipient.value.trim(),
                amount: Number(form.amount.value),
                description: form.description.value.trim()
            })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || "Transfer failed");

        document.getElementById("balance-value").textContent = formatMoney(data.balance);
        form.reset();
        showMessage(messageBox, data.message, "success");
        await loadDashboard();
    } catch (error) {
        showMessage(messageBox, error.message);
    } finally {
        button.disabled = false;
        button.textContent = "Transfer";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const loginError = document.getElementById("login-error");
    if (loginError) {
        const message = new URLSearchParams(window.location.search).get("error");
        if (message) showMessage(loginError, message);
    }

    const transferForm = document.getElementById("transfer-form");
    if (transferForm) {
        transferForm.addEventListener("submit", submitTransfer);
        loadDashboard();
    }
});
