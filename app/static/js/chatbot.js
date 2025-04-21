document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("chat-form");
    const input = document.getElementById("chat-input");
    const log = document.getElementById("chat-log");

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = input.value;
        log.innerHTML += `<p><strong>👨 You:</strong> ${msg}</p>`;
        input.value = "";

        const response = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: msg }),
        });

        const data = await response.json();
        log.innerHTML += `<p><strong>🤖 Bot:</strong> ${data.reply}</p>`;
        log.scrollTop = log.scrollHeight;
    });
});
