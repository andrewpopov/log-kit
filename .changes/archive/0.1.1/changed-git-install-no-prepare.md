---
kind: changed
summary: Installing from git no longer runs a full dependency install: the `prepare` script is gone (run `npm run hooks` once after cloning) and `build` is now `compile`
---

npm 11 runs a full `npm install` (devDependencies included) inside a git clone when package.json has a `prepare` or `build` script. `dist/` is committed, so neither is needed at install time.
