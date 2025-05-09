document.addEventListener("DOMContentLoaded", function () {
    const aiForm = document.getElementById("ai-form-scanner-form");
    const output = document.getElementById("ai-scan-output");

    if (aiForm) {
        aiForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const url = document.getElementById("ai-url-input").value.trim();
            if (!url) return;

            output.textContent = "🔍 Scanning with AI...";

            try {
                const res = await fetch("/ai_test", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url })
                });

                const data = await res.json();
                output.textContent = JSON.stringify(data, null, 2);
            } catch (err) {
                output.textContent = "❌ Failed to scan:\n" + err.message;
            }
        });
    }
});
