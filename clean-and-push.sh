#!/bin/bash
# Clean up node_modules and push a clean repo to GitHub

cd ~/Documents/KunleDevFolder/Candidate5_Auth

# Remove node_modules and cache
rm -rf node_modules

# Ensure .gitignore exists and includes node_modules
if ! grep -q "node_modules/" .gitignore 2>/dev/null; then
  echo "node_modules/" >> .gitignore
fi

# Remove node_modules from git index and add .gitignore
git add .gitignore
git rm -r --cached node_modules

git add .
git commit -m "Remove node_modules and add .gitignore"
git push -u origin main --force 