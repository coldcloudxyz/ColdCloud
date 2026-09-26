/* ============================================================
   ColdCloud Landing Page — main.js
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {

  // ── Scroll Reveal ─────────────────────────────────────────
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible')
        revealObserver.unobserve(entry.target)
      }
    })
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' })

  document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el))


  // ── Mobile Nav ────────────────────────────────────────────
  const navToggle = document.getElementById('nav-toggle')
  const navMobile = document.getElementById('nav-mobile')

  function closeMobileNav() {
    if (!navMobile) return
    navMobile.classList.remove('open')
    if (navToggle) {
      navToggle.textContent = '☰'
      navToggle.setAttribute('aria-expanded', 'false')
    }
    // Always restore body scroll — never leave it locked
    document.body.style.overflow = ''
  }

  if (navToggle && navMobile) {
    navToggle.addEventListener('click', (e) => {
      e.stopPropagation()
      const isOpen = navMobile.classList.toggle('open')
      navToggle.setAttribute('aria-expanded', String(isOpen))
      navToggle.textContent = isOpen ? '✕' : '☰'
      document.body.style.overflow = isOpen ? 'hidden' : ''
    })

    // Close when any link inside mobile nav is clicked
    // Do NOT preventDefault here — navigation links must work
    navMobile.addEventListener('click', (e) => {
      if (e.target.closest('a')) closeMobileNav()
    })

    // Close when clicking outside
    document.addEventListener('click', (e) => {
      if (navMobile.classList.contains('open') &&
          !navMobile.contains(e.target) &&
          !navToggle.contains(e.target)) {
        closeMobileNav()
      }
    })

    // Close on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeMobileNav()
    })
  }


  // ── Sticky Nav Shadow ─────────────────────────────────────
  const nav = document.querySelector('.nav')
  window.addEventListener('scroll', () => {
    if (nav) nav.style.boxShadow = window.scrollY > 10 ? '0 1px 12px rgba(0,0,0,.08)' : 'none'
  }, { passive: true })


  // ── Active Nav Link on Scroll ──────────────────────────────
  const anchorNavLinks = document.querySelectorAll('.nav-links a[href^="#"], #nav-mobile a[href^="#"]')
  new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id
        anchorNavLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === '#' + id)
        })
      }
    })
  }, { threshold: 0.4 }).observe.length > -1 &&
  document.querySelectorAll('section[id]').forEach(s => {
    new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          anchorNavLinks.forEach(link => {
            link.classList.toggle('active', link.getAttribute('href') === '#' + entry.target.id)
          })
        }
      })
    }, { threshold: 0.4 }).observe(s)
  })


  // ── Animated Counters ─────────────────────────────────────
  new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return
      const el = entry.target
      const target = parseFloat(el.dataset.count)
      const suffix = el.dataset.suffix || ''
      const t0 = performance.now()
      const tick = (now) => {
        const p = Math.min((now - t0) / 1200, 1)
        el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + suffix
        if (p < 1) requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    })
  }, { threshold: 0.5 }).observe.length > -1 &&
  document.querySelectorAll('[data-count]').forEach(el => {
    new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return
        const target = parseFloat(el.dataset.count)
        const suffix = el.dataset.suffix || ''
        const t0 = performance.now()
        const tick = (now) => {
          const p = Math.min((now - t0) / 1200, 1)
          el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))) + suffix
          if (p < 1) requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      })
    }, { threshold: 0.5 }).observe(el)
  })


  // ── Activity Feed Simulation ───────────────────────────────
  const feedItems = [
    { icon: '💬', cls: 'wa',   name: 'Sarah Johnson', desc: 'Step 1 — WhatsApp', time: 'just now', status: 'sent',  statusCls: 'sent' },
    { icon: '↩️', cls: 'rep',  name: 'David Park',    desc: 'Replied!',           time: '2m ago',   status: 'reply', statusCls: 'recv' },
    { icon: '📱', cls: 'sms',  name: 'Maria Torres',  desc: 'Step 2 — SMS',       time: '5m ago',   status: 'sent',  statusCls: 'sent' },
    { icon: '📞', cls: 'call', name: 'James Wilson',  desc: 'Step 3 — Call',      time: '12m ago',  status: 'sent',  statusCls: 'sent' },
    { icon: '💬', cls: 'wa',   name: 'Anna Chen',     desc: 'Step 4 — Final WA',  time: '18m ago',  status: 'sent',  statusCls: 'sent' },
  ]

  const feedEl = document.getElementById('hero-feed')
  if (feedEl) {
    const renderFeed = (items) => {
      feedEl.innerHTML = items.map((item, i) => `
        <div class="feed-item" style="animation-delay:${i * 0.08}s">
          <div class="feed-icon ${item.cls}">${item.icon}</div>
          <div class="feed-content">
            <div class="feed-name">${item.name}</div>
            <div class="feed-desc">${item.desc}</div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px">
            <div class="feed-time">${item.time}</div>
            <div class="feed-status ${item.statusCls}">${item.status}</div>
          </div>
        </div>
      `).join('')
    }
    renderFeed(feedItems)

    const newReplies = [
      { name: 'Tom Richards',  msg: "Yes, I'm still interested!" },
      { name: 'Lisa Nguyen',   msg: 'Can we chat tomorrow?' },
      { name: 'Carlos Mendez', msg: 'What are the prices?' },
      { name: 'Emma Sullivan', msg: 'Thanks for following up!' },
    ]
    let replyIdx = 0
    setInterval(() => {
      const r = newReplies[replyIdx++ % newReplies.length]
      feedItems.forEach(item => {
        if (item.time === 'just now') item.time = '1m ago'
        else if (item.time === '1m ago') item.time = '2m ago'
      })
      feedItems.unshift({ icon: '↩️', cls: 'rep', name: r.name, desc: 'Replied!', time: 'just now', status: 'reply', statusCls: 'recv' })
      if (feedItems.length > 5) feedItems.pop()
      renderFeed(feedItems)
    }, 4000)
  }


  // ── Smooth scroll — ONLY for true #anchor links ───────────
  // Uses strict href^="#" selector so it NEVER intercepts
  // navigation links like ../app/index.html?mode=signup
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href')
      if (!href || href === '#') return   // bare # — do nothing
      const target = document.querySelector(href)
      if (!target) return                  // no matching element — let browser handle
      e.preventDefault()
      const top = target.getBoundingClientRect().top + window.scrollY - 72
      window.scrollTo({ top, behavior: 'smooth' })
      closeMobileNav()
    })
  })


  // ── CTA email form ────────────────────────────────────────
  document.querySelectorAll('.cta-email-form').forEach(form => {
    form.addEventListener('submit', (e) => {
      e.preventDefault()
      const input = form.querySelector('input[type="email"]')
      if (input && input.value.trim()) {
        const btn = form.querySelector('button')
        const orig = btn.textContent
        btn.textContent = "✓ You're on the list"
        btn.disabled = true
        input.value = ''
        setTimeout(() => { btn.textContent = orig; btn.disabled = false }, 4000)
      }
    })
  })

})
