#!/usr/bin/env node
/** Generate favicon and apple-touch-icon from the login logo. Run before vite build. */
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import sharp from 'sharp'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')
const LOGO_SRC = path.join(ROOT, 'src', 'assets', 'logo-dark.png')
const PUBLIC = path.join(ROOT, 'public')

async function main() {
  if (!fs.existsSync(LOGO_SRC)) {
    console.error('Logo not found:', LOGO_SRC)
    process.exit(1)
  }
  if (!fs.existsSync(PUBLIC)) {
    fs.mkdirSync(PUBLIC, { recursive: true })
  }

  const faviconPath = path.join(PUBLIC, 'favicon.png')
  const appleTouchPath = path.join(PUBLIC, 'apple-touch-icon.png')

  await sharp(LOGO_SRC)
    .resize(32, 32)
    .png()
    .toFile(faviconPath)

  await sharp(LOGO_SRC)
    .resize(180, 180)
    .png()
    .toFile(appleTouchPath)

  console.log('  ✓ favicon.png')
  console.log('  ✓ apple-touch-icon.png')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
