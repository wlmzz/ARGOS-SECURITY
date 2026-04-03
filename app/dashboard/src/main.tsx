import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'

// Load Montserrat from Google Fonts
const link = document.createElement('link')
link.rel = 'stylesheet'
link.href = 'https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700;800&display=swap'
document.head.appendChild(link)

const style = document.createElement('style')
style.textContent = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body, #root { height: 100%; }
  body {
    background: #0a0a0a;
    color: #ffffff;
    font-family: 'Montserrat', 'Segoe UI', sans-serif;
    font-size: 13px;
    font-weight: 400;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }

  /* ── Scrollbars ─────────────────────────────── */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

  input, button, textarea { font-family: inherit; }
  * { outline: none; }

  /* ── Keyframes ──────────────────────────────── */
  @keyframes pulse-dot {
    0%,100% { opacity:1; box-shadow: 0 0 0 0 rgba(34,197,94,0.4); }
    50%      { opacity:0.6; box-shadow: 0 0 0 4px rgba(34,197,94,0); }
  }
  @keyframes fadeSlide {
    from { opacity:0; transform:translateY(-6px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes fadeIn {
    from { opacity:0; }
    to   { opacity:1; }
  }
  @keyframes scan {
    0%   { transform: translateY(-100%); }
    100% { transform: translateY(100vh); }
  }
  @keyframes typing-dot {
    0%,60%,100% { opacity:0.2; transform:translateY(0); }
    30%          { opacity:1;   transform:translateY(-3px); }
  }

  /* ── Map animations ─────────────────────────── */
  @keyframes map-pulse-ring {
    0%   { transform: scale(1);   opacity: 0.7; }
    100% { transform: scale(3.5); opacity: 0; }
  }
  @keyframes attack-dash {
    to { stroke-dashoffset: -22; }
  }
  .attack-dash-line {
    stroke-dasharray: 6 5 !important;
    animation: attack-dash 0.9s linear infinite !important;
  }

  /* ── Leaflet dark theme ─────────────────────── */
  .leaflet-container { background: #0a0a0a !important; font-family: inherit; }
  .leaflet-popup-content-wrapper {
    background: #161616;
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 6px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.7);
    color: #ffffff;
  }
  .leaflet-popup-tip { background: #161616; }
  .leaflet-popup-close-button { color: #666 !important; }
  .leaflet-control-attribution { display: none !important; }
  .leaflet-popup-content { margin: 0; }
`
document.head.appendChild(style)

createRoot(document.getElementById('root')!).render(
  <StrictMode><App /></StrictMode>
)
