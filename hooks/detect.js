#!/usr/bin/env node
// Detects project languages/frameworks by file extensions and config files.
// Output: JSON array of language names, or empty array if nothing detected.
// Usage: node hooks/detect.js [dir]
// Env: DETECT_OUT = "json" (default) or "csv"
'use strict';

const fs = require('fs');
const path = require('path');

const DIR = process.argv[2] || process.cwd();
const OUT = process.env.DETECT_OUT || 'json';

// Extension → language mapping
const EXT_MAP = {
  '.py': 'python', '.pyw': 'python',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.go': 'go',
  '.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
  '.rs': 'rust',
  '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.hpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
  '.swift': 'swift',
  '.scala': 'scala',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
  '.sql': 'sql',
  '.html': 'html', '.htm': 'html',
  '.css': 'css', '.scss': 'scss', '.less': 'less',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json',
  '.toml': 'toml',
  '.dockerfile': 'docker',
  '.tf': 'terraform', '.tfvars': 'terraform',
};

// Config file → language/framework mapping
const CONFIG_MAP = {
  'package.json': 'javascript',
  'tsconfig.json': 'typescript',
  'deno.json': 'typescript',
  'deno.jsonc': 'typescript',
  'go.mod': 'go',
  'go.sum': 'go',
  'Cargo.toml': 'rust',
  'pom.xml': 'java',
  'build.gradle': 'java',
  'build.gradle.kts': 'kotlin',
  'Gemfile': 'ruby',
  'requirements.txt': 'python',
  'setup.py': 'python',
  'setup.cfg': 'python',
  'pyproject.toml': 'python',
  'Pipfile': 'python',
  'poetry.lock': 'python',
  'composer.json': 'php',
  'CMakeLists.txt': 'cpp',
  'Makefile': 'c',
  'Dockerfile': 'docker',
  'docker-compose.yml': 'docker',
  'docker-compose.yaml': 'docker',
  'tfplan': 'terraform',
  'main.tf': 'terraform',
  // Modern JS frameworks
  'next.config.js': 'javascript',
  'next.config.mjs': 'javascript',
  'next.config.ts': 'typescript',
  'nuxt.config.ts': 'typescript',
  'nuxt.config.js': 'javascript',
  'svelte.config.js': 'javascript',
  'svelte.config.ts': 'typescript',
  'remix.config.js': 'javascript',
  'astro.config.mjs': 'javascript',
  'astro.config.ts': 'typescript',
  'astro.config.js': 'javascript',
};

// Directories to skip
const SKIP = new Set(['node_modules', '.git', 'vendor', '__pycache__', 'dist', 'build', '.next', '.nuxt', 'target', 'bin', 'obj']);

function walk(dir, depth = 0) {
  if (depth > 6) return [];
  const results = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.name.startsWith('.') && e.name !== '.env' && e.name !== '.dockerfile') continue;
      if (SKIP.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        results.push(...walk(full, depth + 1));
      } else {
        const ext = path.extname(e.name).toLowerCase();
        const base = e.name.toLowerCase();
        // Check extension
        if (EXT_MAP[ext]) {
          results.push(EXT_MAP[ext]);
        }
        // Check config files
        if (CONFIG_MAP[base]) {
          results.push(CONFIG_MAP[base]);
        }
        // Check Dockerfile variants
        if (base.startsWith('dockerfile')) {
          results.push('docker');
        }
        // Check .csproj
        if (base.endsWith('.csproj')) {
          results.push('csharp');
        }
      }
    }
  } catch (e) {
    // skip unreadable dirs
  }
  return results;
}

const langs = [...new Set(walk(DIR))].sort();
if (OUT === 'csv') {
  console.log(langs.join(','));
} else {
  console.log(JSON.stringify(langs));
}
