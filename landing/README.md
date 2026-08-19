# ColdCloud Landing Page

Clean, production-ready landing page for ColdCloud — follow-up automation for businesses.

## Project structure

```
coldcloud-landing/
├── index.html          ← Main landing page
├── styles/
│   └── main.css        ← All styles (reset, layout, components, responsive)
├── scripts/
│   └── main.js         ← Scroll animations, mobile nav, counter animations, feed simulation
├── assets/
│   ├── logo.svg        ← Brand logo
│   └── icons/
│       ├── whatsapp.svg
│       ├── sms.svg
│       └── call.svg
└── README.md
```

## Features

- Fully responsive (mobile, tablet, desktop)
- Scroll reveal animations
- Live activity feed simulation in hero
- Animated counters
- Mobile navigation menu
- Sticky nav with scroll shadow
- Smooth scroll for anchor links
- Accessible markup (ARIA labels, semantic HTML)
- Zero dependencies — plain HTML, CSS, JS

## Sections

1. **Navigation** — sticky, mobile-responsive
2. **Hero** — headline, CTA, live app mockup
3. **Proof bar** — key statistics
4. **Problem** — why leads go cold, stat block
5. **Solution** — 3 cards (multi-channel, personalisation, sequences)
6. **Features** — 6 feature cards
7. **How it works** — 4-step process
8. **Channels** — WhatsApp, SMS, calls with open rates
9. **Sequence visual** — 4-step sequence breakdown
10. **Testimonials** — 3 cards
11. **Pricing** — Free + Pro
12. **Final CTA** — dark call to action block
13. **Footer** — links, brand, copyright

## Deploy

### Vercel (recommended)
```bash
# Install Vercel CLI
npm install -g vercel

# Deploy from the landing folder
cd coldcloud-landing
vercel
```

### Netlify
1. Go to netlify.com → New site → Deploy manually
2. Drag and drop the `coldcloud-landing/` folder
3. Done

### GitHub Pages
1. Push to a GitHub repository
2. Go to Settings → Pages
3. Set source to main branch, root folder
4. Your site is live at `https://username.github.io/repo-name`

## Connecting to the app

Update all `href="app.html"` links to point to your deployed ColdCloud app URL:

```html
<!-- Before -->
<a href="app.html">Get started free</a>

<!-- After -->
<a href="https://app.coldcloud.io">Get started free</a>
```

## Customisation

- **Colors** — edit `:root` variables at the top of `styles/main.css`
- **Copy** — all text is in `index.html`, clearly structured
- **Pricing** — update the pricing cards in the pricing section
- **CTA links** — search for `app.html` and replace with your real app URL
- **Email** — search for `hello@coldcloud.io` and replace

## Tech

- Plain HTML5, CSS3, vanilla JS (ES6+)
- Google Fonts: Inter + JetBrains Mono
- No frameworks, no build step, no dependencies
- Ready to convert to React/Next.js if needed
