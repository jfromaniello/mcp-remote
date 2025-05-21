#!/bin/bash
sed -i '' 's/debugLog(global\.currentServerUrlHash!, /debugLog(/g' src/lib/coordination.ts
sed -i '' 's/debugLog(serverUrlHash, /debugLog(/g' src/lib/coordination.ts