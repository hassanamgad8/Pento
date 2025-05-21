document.addEventListener("DOMContentLoaded", function () {
    // Matrix background effect
    const canvas = document.getElementById('matrix');
    if (!canvas) {
        console.error('Matrix canvas element not found.');
        return;
    }

    const ctx = canvas.getContext('2d');

    // Set canvas size
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Matrix rain effect
    const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const fontSize = 28;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);

    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.005)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font = `bold ${fontSize}px monospace`;
        drops.forEach((y, index) => {
            const text = characters[Math.floor(Math.random() * characters.length)];
            ctx.shadowColor = '#00ff00';
            ctx.shadowBlur = 16;
            ctx.fillStyle = '#00ff00';
            ctx.fillText(text, index * fontSize, y * fontSize);
            ctx.shadowBlur = 0;
            if (y * fontSize > canvas.height && Math.random() > 0.975) {
                drops[index] = 0;
            }
            drops[index]++;
        });
    }

    setInterval(drawMatrix, 50);

    // Tool link hover effect (only if tool links are present)
    const toolLinks = document.querySelectorAll('.tool-link');
    if (toolLinks.length > 0) {
        toolLinks.forEach(link => {
            link.addEventListener('mouseenter', () => {
                const hoverElement = link.querySelector('.tool-hover');
                if (hoverElement) {
                    hoverElement.style.width = '100%';
                }
            });

            link.addEventListener('mouseleave', () => {
                const hoverElement = link.querySelector('.tool-hover');
                if (hoverElement) {
                    hoverElement.style.width = '0%';
                }
            });
        });
    }

    // Modal functionality (only if tool links are present)
    const modalOverlay = document.createElement('div');
    modalOverlay.classList.add('modal-overlay');
    document.body.appendChild(modalOverlay);

    toolLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            if (document.querySelector('.modal')) return;

            const url = link.getAttribute('href');
            fetch(url)
                .then(response => response.text())
                .then(html => {
                    const modal = document.createElement('div');
                    modal.classList.add('modal');
                    modal.innerHTML = html;

                    const closeButton = document.createElement('button');
                    closeButton.textContent = 'Close';
                    closeButton.classList.add('modal-close');
                    closeButton.addEventListener('click', closeModal);

                    modal.appendChild(closeButton);
                    document.body.appendChild(modal);
                    modalOverlay.classList.add('active');
                })
                .catch(error => console.error('Error loading modal content:', error));
        });
    });

    modalOverlay.addEventListener('click', closeModal);

    function closeModal() {
        const activeModal = document.querySelector('.modal');
        if (activeModal) activeModal.remove();
        modalOverlay.classList.remove('active');
    }

    // Glitch effect for headings
    const glitchElements = document.querySelectorAll('.glitch-effect');
    
    function applyGlitchEffect(element) {
        let originalText = element.textContent;
        let glitchText = originalText;
        let glitchInterval;

        element.addEventListener('mouseenter', () => {
            glitchInterval = setInterval(() => {
                glitchText = originalText.split('').map(char => {
                    return Math.random() < 0.1 ? characters[Math.floor(Math.random() * characters.length)] : char;
                }).join('');
                element.textContent = glitchText;
            }, 100);
        });

        element.addEventListener('mouseleave', () => {
            clearInterval(glitchInterval);
            element.textContent = originalText;
        });
    }

    glitchElements.forEach(applyGlitchEffect);
});
