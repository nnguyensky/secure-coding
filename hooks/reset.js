#!/usr/bin/env node
// Clears the per-session findings and regenerates an empty report.
// Run at the start of each session so the report reflects only this session.
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, writeState, helpRequested } = require('./config');

// --help must print help, never run the tool. This used to wipe the findings
// file when asked for help.
const USAGE = `Usage: node hooks/reset.js\n\nClears the per-session findings file and regenerates an empty report.\nRun at the start of a session so the report reflects only that session.\n\nEnv: SECURE_CODING_STATE (default: <project>/checks/findings.jsonl)`;
if (helpRequested(process.argv.slice(2), USAGE)) process.exit(0);

const DIR = path.resolve(__dirname, '..');
const STATE = statePath('findings.jsonl', 'SECURE_CODING_STATE');

writeState(STATE, '');

try { require(path.join(DIR, 'hooks', 'report.js')); } catch (e) { /* best-effort */ }
process.stderr.write('secure-coding: findings reset for a new session\n');
