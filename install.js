#!/usr/bin/env node
// Forwarding entrypoint: allows running `node install.js` directly from the skill root.
'use strict';
const install = require('./hooks/install.js');
if (typeof install.main === 'function') {
  install.main();
}
