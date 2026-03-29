// ============================================================
// CyberX — Global JavaScript
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    /* ── Loading bar ──────────────────────────────────────── */
    const loadingBar = document.querySelector('.loading-bar');
    if (loadingBar) {
        setTimeout(() => loadingBar.classList.add('done'), 1800);
        setTimeout(() => loadingBar.remove(), 2200);
    }

    /* ── Navbar scroll effect ─────────────────────────────── */
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        const onScroll = () => {
            navbar.classList.toggle('scrolled', window.scrollY > 24);
        };
        window.addEventListener('scroll', onScroll, { passive: true });
        onScroll();
    }

    /* ── Mobile hamburger toggle ──────────────────────────── */
    const toggle = document.getElementById('nav-toggle');
    const navLinks = document.getElementById('nav-links');
    if (toggle && navLinks) {
        toggle.addEventListener('click', () => {
            toggle.classList.toggle('active');
            navLinks.classList.toggle('open');
            document.body.style.overflow = navLinks.classList.contains('open') ? 'hidden' : '';
        });

        // Close mobile nav on link click
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    toggle.classList.remove('active');
                    navLinks.classList.remove('open');
                    document.body.style.overflow = '';
                }
            });
        });
    }

    /* ── Mobile dropdown toggle ───────────────────────────── */
    const dropdowns = document.querySelectorAll('.nav-dropdown');
    dropdowns.forEach(dd => {
        const trigger = dd.querySelector(':scope > a');
        if (trigger) {
            trigger.addEventListener('click', (e) => {
                if (window.innerWidth <= 768) {
                    e.preventDefault();
                    dd.classList.toggle('open');
                }
            });
        }
    });

    /* ── Card parallax tilt ───────────────────────────────── */
    if (!window.location.pathname.includes('/email-validation/')) {
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;
                const cx = rect.width / 2;
                const cy = rect.height / 2;
                const rx = (y - cy) / 12;
                const ry = (cx - x) / 12;
                card.style.transform = `perspective(1000px) rotateX(${rx}deg) rotateY(${ry}deg) translateY(-4px)`;
            });
            card.addEventListener('mouseleave', () => {
                card.style.transform = '';
            });
        });
    }

    /* ── Fade-in on scroll (Intersection Observer) ────────── */
    const fadeEls = document.querySelectorAll('.fade-in-up');
    if (fadeEls.length && 'IntersectionObserver' in window) {
        const io = new IntersectionObserver((entries) => {
            entries.forEach(e => {
                if (e.isIntersecting) {
                    e.target.style.animationPlayState = 'running';
                    io.unobserve(e.target);
                }
            });
        }, { threshold: 0.15 });
        fadeEls.forEach(el => {
            el.style.animationPlayState = 'paused';
            io.observe(el);
        });
    }

    /* ── Active nav link highlight ────────────────────────── */
    const path = window.location.pathname;
    document.querySelectorAll('.nav-links a[href]').forEach(a => {
        const href = a.getAttribute('href');
        if (href && href !== '/' && path.startsWith(href)) {
            a.classList.add('active');
        } else if (href === '/' && path === '/') {
            a.classList.add('active');
        }
    });
});