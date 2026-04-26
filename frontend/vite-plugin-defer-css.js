/** Vite plugin: defer main CSS to avoid render-blocking. Converts stylesheet links to load async via media="print" onload, adds noscript fallback for no-JS users. */
export default function deferCss() {
  return {
    name: 'defer-css',
    enforce: 'post',
    transformIndexHtml(html) {
      // Match Vite-injected stylesheet: <link rel="stylesheet" href="/assets/..." ...>
      const linkRe = /<link\s+rel=["']stylesheet["'][^>]*href=["'](\/assets\/[^"']+\.css)["'][^>]*>/gi
      return html.replace(linkRe, (match, href) => {
        const deferTag = `<link rel="stylesheet" href="${href}" media="print" onload="this.media='all'">`
        const noscriptTag = `<noscript><link rel="stylesheet" href="${href}"></noscript>`
        return deferTag + noscriptTag
      })
    },
  }
}
