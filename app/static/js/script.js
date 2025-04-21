document.addEventListener("DOMContentLoaded", function () {
    const dashboardBtn = document.getElementById("dashboard-btn");
    const newScanBtn = document.getElementById("new-scan-btn");
    const reportsBtn = document.getElementById("reports-btn");
    const attackSurfaceBtn = document.getElementById("attack-surface-btn");
    const assetsBtn = document.getElementById("assets-btn");
    const findingsBtn = document.getElementById("findings-btn");
    const chatbotBtn = document.getElementById("chatbot-btn");
    const mainContent = document.getElementById("main-content");

    // Utility to fetch and load content into #main-content
    function loadPage(url) {
        fetch(url)
            .then((response) => response.text())
            .then((html) => {
                mainContent.innerHTML = html;

                // If it's the chatbot, hook up chat events
                if (url === "/chatbot_component") {
                    const form = document.getElementById("chat-form");
                    const input = document.getElementById("chat-input");
                    const log = document.getElementById("chat-log");

                    form.addEventListener("submit", async (e) => {
                        e.preventDefault();

                        const msg = input.value.trim();
                        if (!msg) return;

                        log.innerHTML += `<p><strong>👨 You:</strong> ${msg}</p>`;
                        input.value = "";

                        // Show loading spinner
                        const spinnerId = `spinner-${Date.now()}`;
                        log.innerHTML += `<p id="${spinnerId}"><em>🤖 Thinking... <span class="spinner">⏳</span></em></p>`;
                        log.scrollTop = log.scrollHeight;

                        try {
                            const response = await fetch("/api/chat", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ message: msg }),
                            });

                            const data = await response.json();
                            const rawReply = (data && data.reply) ? data.reply : "❌ No reply from server.";

                            // Remove spinner
                            const spinnerElement = document.getElementById(spinnerId);
                            if (spinnerElement) spinnerElement.remove();

                            // Escape HTML
                            const escapedReply = rawReply
                                .replace(/</g, "&lt;")
                                .replace(/>/g, "&gt;");

                            // Animate typing of the reply
                            const pre = document.createElement("pre");
                            pre.classList.add("bot-reply");
                            log.appendChild(pre);

                            let i = 0;
                            function typeChar() {
                                if (i < escapedReply.length) {
                                    pre.innerHTML += escapedReply[i] === "\n" ? "<br>" : escapedReply[i];
                                    i++;
                                    setTimeout(typeChar, 5); // Typing speed
                                    log.scrollTop = log.scrollHeight;
                                }
                            }
                            typeChar();

                        } catch (err) {
                            const spinnerElement = document.getElementById(spinnerId);
                            if (spinnerElement) spinnerElement.remove();

                            log.innerHTML += `<p><strong>❌ Error:</strong> ${err.message}</p>`;
                            log.scrollTop = log.scrollHeight;
                        }
                    });
                }
            })
            .catch((err) => {
                mainContent.innerHTML = "<p>❌ Failed to load page.</p>";
                console.error("Page load error:", err);
            });
    }

    // Sidebar buttons
    if (dashboardBtn) dashboardBtn.addEventListener("click", () => loadPage("/dashboard"));
    if (newScanBtn) newScanBtn.addEventListener("click", () => loadPage("/new_scan")); // adjust if needed
    if (reportsBtn) reportsBtn.addEventListener("click", () => loadPage("/reports"));   // adjust if needed
    if (attackSurfaceBtn) attackSurfaceBtn.addEventListener("click", () => loadPage("/attack_surface")); // adjust if needed
    if (assetsBtn) assetsBtn.addEventListener("click", () => loadPage("/assets"));       // adjust if needed
    if (findingsBtn) findingsBtn.addEventListener("click", () => loadPage("/findings")); // adjust if needed
    if (chatbotBtn) chatbotBtn.addEventListener("click", () => loadPage("/chatbot_component"));
});
