import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
// Bundle the stylesheet through Vite so it gets a content-hashed filename and
// is injected into index.html. This keeps the CSS versioned in lockstep with
// the JS bundle — a fresh index.html can never pair new markup with a stale,
// CDN-cached /static/style.css (the skew that broke mobile right after deploy).
import '../../app/static/style.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
