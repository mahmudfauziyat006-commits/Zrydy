(function () {
    const body = document.body;
    const toggle = document.querySelector('[data-theme-toggle]');
    const savedTheme = localStorage.getItem('zrydy-theme');

    function applyTheme(theme) {
        body.classList.toggle('dark-mode', theme === 'dark');
        body.classList.toggle('light-mode', theme === 'light');
        if (toggle) {
            toggle.textContent = theme === 'dark' ? 'Light mode' : 'Dark mode';
            toggle.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
        }
    }

    applyTheme(savedTheme === 'light' ? 'light' : 'dark');
    if (toggle) {
        toggle.addEventListener('click', function () {
            const nextTheme = body.classList.contains('dark-mode') ? 'light' : 'dark';
            localStorage.setItem('zrydy-theme', nextTheme);
            applyTheme(nextTheme);
        });
    }
})();
