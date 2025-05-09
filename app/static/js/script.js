document.addEventListener("DOMContentLoaded", function () {
    const mainContent = document.getElementById("main-content");

    const routes = {
        "dashboard-btn": null,  // Full reload for dashboard
        "attack-surface-btn": "/attack_surface",
        "findings-btn": "/findings",
        "assets-btn": "/assets",
        "reports-btn": "/reports",
        "new-scan-btn": "/new_scan",
        "chatbot-btn": "/chatbot_component"
    };

    Object.entries(routes).forEach(([btnId, route]) => {
        const btn = document.getElementById(btnId);
        if (btn) {
            btn.addEventListener("click", () => {
                if (route === null) {
                    // Reload dashboard fully
                    window.location.href = "/";
                    return;
                }

                fetch(route)
                    .then((res) => res.text())
                    .then((html) => {
                        mainContent.innerHTML = html;

                        // Handle chatbot form logic
                        if (route === "/chatbot_component") {
                            const form = document.getElementById("chat-form");
                            const input = document.getElementById("chat-input");
                            const log = document.getElementById("chat-log");

                            form.addEventListener("submit", async (e) => {
                                e.preventDefault();
                                const msg = input.value.trim();
                                if (!msg) return;

                                log.innerHTML += `<p><strong>👨 You:</strong> ${msg}</p>`;
                                input.value = "";

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
                                    const rawReply = data?.reply || "❌ No reply from server.";

                                    document.getElementById(spinnerId)?.remove();

                                    const escapedReply = rawReply.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                                    const pre = document.createElement("pre");
                                    pre.classList.add("bot-reply");
                                    log.appendChild(pre);

                                    let i = 0;
                                    function typeChar() {
                                        if (i < escapedReply.length) {
                                            pre.innerHTML += escapedReply[i] === "\n" ? "<br>" : escapedReply[i];
                                            i++;
                                            setTimeout(typeChar, 5);
                                            log.scrollTop = log.scrollHeight;
                                        }
                                    }
                                    typeChar();
                                } catch (err) {
                                    document.getElementById(spinnerId)?.remove();
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
            });
        }
    });
});
