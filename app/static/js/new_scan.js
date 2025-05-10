function switchTab(tabName, clickedBtn) {
    const sections = ['quick', 'recon', 'vuln', 'exploit', 'utils'];
    sections.forEach(name => {
        document.getElementById('tab-' + name)?.classList.add('hidden');
    });

    document.getElementById('tab-' + tabName)?.classList.remove('hidden');

    document.querySelectorAll('.tool-tab-btn').forEach(btn =>
        btn.classList.remove('tab-active')
    );
    clickedBtn.classList.add('tab-active');
}

// Set default tab after DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
    document.querySelector('.tool-tab-btn[onclick*="recon"]')?.click();
});
