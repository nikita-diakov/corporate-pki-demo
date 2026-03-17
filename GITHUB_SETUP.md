# GitHub Setup (mini project)

## 1) Create the repository
On GitHub: **New repository** → name: `corporate-pki-demo` → Public → create.

## 2) Push the code
```bash
cd corporate-pki-demo
git init
git add .
git commit -m "Initial commit: corporate-pki-demo"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/corporate-pki-demo.git
git push -u origin main
```

## 3) Add screenshots
Create `assets/screenshots/` and add 3–5 images:
- status.png
- enroll.png
- sign.png
- verify.png
- revoke.png (optional)

Commit and push.

## 4) Enable GitHub Pages
GitHub → **Settings → Pages** → Deploy from branch → `main` → `/docs`.

Your page: `https://<YOUR_USERNAME>.github.io/corporate-pki-demo/`

## 5) Create a Release
GitHub → Releases → Draft a new release:
- Tag: `v1.0.0`
- Title: `corporate-pki-demo v1.0.0`
- Attach a zip of the repo
