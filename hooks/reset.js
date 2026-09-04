#!/usr/bin/env node
// Clears the per-session findings and regenerates an empty report.
// Run at the start of each session so the report reflects only this session.
'use strict';

const fs = require('fs');
const path = require('path');
const { statePath, writeState } = require('./config');

const DIR = path.resolve(__dirname, '..');
const STATE = statePath('findings.jsonl', 'SECURE_CODING_STATE');

writeState(STATE, '');

try { require(path.join(DIR, 'hooks', 'report.js')); } catch (e) { /* best-effort */ }
process.stderr.write('secure-coding: findings reset for a new session\n');
