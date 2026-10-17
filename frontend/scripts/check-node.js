// Enforce Node version for Vite build (avoids crypto.hash and similar issues).
const minMajor = 20;
const minMinor = 9;
const v = process.versions.node.split('.').map(Number);
const major = v[0] || 0;
const minor = v[1] || 0;
if (major < minMajor || (major === minMajor && minor < minMinor)) {
  console.error(
    `frontend build requires Node.js ${minMajor}.${minMinor}+. Current: ${process.versions.node}. ` +
    'Upgrade Node (e.g. nvm install 22 && nvm use 22) and try again.'
  );
  process.exit(1);
}
