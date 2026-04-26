#!/usr/bin/env node
/** Convert PNG/JPEG assets to WebP for smaller load times. Creates .webp alongside originals. Run before vite build. */
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import sharp from 'sharp'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')

const DIRS = [
  path.join(ROOT, 'public', 'bg'),
  path.join(ROOT, 'src', 'assets'),
]

const EXTENSIONS = ['.png', '.jpg', '.jpeg']

async function convertToWebP(dir) {
  if (!fs.existsSync(dir)) return
  const files = fs.readdirSync(dir)
  let converted = 0
  for (const file of files) {
    const ext = path.extname(file).toLowerCase()
    if (!EXTENSIONS.includes(ext)) continue
    
    // Prevent path traversal: only use the basename (no directory components)
    const safeFilename = path.basename(file)
    const srcPath = path.join(dir, safeFilename)
    
    // Validate that the resolved path is still within the intended directory
    const resolvedSrcPath = path.resolve(srcPath)
    const resolvedDir = path.resolve(dir)
    if (!resolvedSrcPath.startsWith(resolvedDir + path.sep)) {
      console.warn(`  ✗ Skipping suspicious path: ${file}`)
      continue
    }
    
    const base = path.join(dir, path.basename(safeFilename, ext))
    const webpPath = base + '.webp'
    try {
      const srcStat = fs.statSync(srcPath)
      const webpStat = fs.existsSync(webpPath) ? fs.statSync(webpPath) : null
      if (webpStat && webpStat.mtimeMs >= srcStat.mtimeMs) continue // skip if WebP is up to date
      await sharp(srcPath)
        .webp({ quality: 85 })
        .toFile(webpPath)
      console.log(`  ✓ ${path.relative(ROOT, webpPath)}`)
      converted++
    } catch (err) {
      console.warn(`  ✗ ${file}: ${err.message}`)
    }
  }
  return converted
}

async function main() {
  let total = 0
  for (const dir of DIRS) {
    if (fs.existsSync(dir)) {
      total += await convertToWebP(dir)
    }
  }
  if (total > 0) {
    console.log(`WebP: converted ${total} image(s)`)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
