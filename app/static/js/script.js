document.addEventListener("DOMContentLoaded", function () {
    const mainContent = document.getElementById("main-content");

    const routes = {
        "dashboard-btn": null,  // Full reload for dashboard
        "attack-surface-btn": "/attack_surface",
        "findings-btn": "/findings",
        "assets-btn": "/assets",
        "reports-btn": "/reports",
        "new-scan-btn": "/new_scan",
        "chatbot-btn": "/chatbot_component",
        "website_scanner-btn": "/website_scanner"  // ✅ Added
    };

    Object.entries(routes).forEach(([btnId, route]) => {
        const btn = document.getElementById(btnId);
        if (btn) {
            btn.addEventListener("click", () => {
                if (route === null) {
                    window.location.href = "/";
                    return;
                }

                fetch(route)
                    .then((res) => res.text())
                    .then((html) => {
                        mainContent.innerHTML = html;

                        // ✅ Load zap scanner for both /new_scan and /website_scanner
                        if (route === "/new_scan" || route === "/website_scanner") {
                            const zapScriptSrc = "/static/js/zap_scanner.js";

                            // Remove existing zap script
                            const existingZAP = Array.from(document.scripts).find(s => s.src.includes(zapScriptSrc));
                            if (existingZAP) existingZAP.remove();

                            const zapScript = document.createElement("script");
                            zapScript.src = zapScriptSrc;
                            zapScript.type = "module";
                            zapScript.defer = true;
                            document.body.appendChild(zapScript);

                            // Only /new_scan has new_scan.js
                            if (route === "/new_scan") {
                                const scanScriptId = "new-scan-script";
                                const oldScript = document.getElementById(scanScriptId);
                                if (oldScript) oldScript.remove();

                                const script = document.createElement("script");
                                script.id = scanScriptId;
                                script.src = "/static/js/new_scan.js";
                                script.defer = true;
                                document.body.appendChild(script);
                            }
                        }

                        // 🤖 Handle chatbot logic
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

document.addEventListener("click", function(e) {
    const card = e.target.closest("#website_scanner-btn");
    if (card) {
        console.log("Website Scanner card clicked");
        e.preventDefault();
        fetch("/website_scanner")
            .then(res => res.text())
            .then(html => {
                document.getElementById("main-content").innerHTML = html;
                // Dynamically import zap_scanner.js as a module after DOM update and call initZapScanner
                import("/static/js/zap_scanner.js").then(mod => {
                    mod.initZapScanner();
                    console.log("zap_scanner.js initialized after DOM update");
                });
            });
    }
});
