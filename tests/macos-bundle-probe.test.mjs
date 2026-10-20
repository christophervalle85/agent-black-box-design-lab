import { test } from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

test('experimental app-bundled probe declares a distinct stable bundle identity',()=>{
 const plist=readFileSync(new URL('../native/macos/SandboxProbe-Info.plist',import.meta.url),'utf8');
 assert.match(plist,/<key>CFBundleIdentifier<\/key>\s*<string>dev\.agentblackbox\.sandbox-probe\.bundle<\/string>/);
 assert.match(plist,/<key>CFBundlePackageType<\/key>\s*<string>APPL<\/string>/);
 assert.match(plist,/<key>CFBundleExecutable<\/key>\s*<string>blackbox-sandbox-probe<\/string>/);
});
test('bundled probe must not make the main MCP gateway claim macOS required support',()=>{
 const sandbox=readFileSync(new URL('../src/sandbox.mjs',import.meta.url),'utf8');
 assert.match(sandbox,/if\(platform!==['"]linux['"]\) throw Error/);
 assert.match(sandbox,/macOS requires a signed App Sandbox helper/);
});
