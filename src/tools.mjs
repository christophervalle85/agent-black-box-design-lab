import { readFileSync, realpathSync, statSync, openSync, writeFileSync, closeSync, constants } from 'node:fs';
import { basename } from 'node:path';
import { resolveWorkspaceFile } from './policy.mjs';

export function createDemoAdapters(workspaceRoot) {
  return {
    'file.read': async args => {
      const check = resolveWorkspaceFile(args.path, workspaceRoot);
      if (!check.ok) throw new Error('Filesystem boundary validation failed at execution time.');
      // Defend against a symlink swapped into place between authorization and execution.
      const target = realpathSync(check.candidate);
      const renewed = resolveWorkspaceFile(args.path, workspaceRoot);
      if (!renewed.ok || realpathSync(renewed.candidate) !== target) throw new Error('Target changed before execution.');
      if (!statSync(target).isFile()) throw new Error('Only ordinary files can be read.');
      if (statSync(target).size > 64 * 1024) throw new Error('File is over the 64 KiB demo limit.');
      const data = readFileSync(target, 'utf8');
      return { value: data, summary: `Read ${Buffer.byteLength(data)} bytes from ${basename(target)}`, simulated: false };
    },
    'file.write': async args => {
      // Re-evaluate at execution time and never overwrite an existing note.
      const check = resolveWorkspaceFile(args.path, workspaceRoot);
      if (!check.ok || !/^[a-z0-9][a-z0-9_-]{0,39}\.txt$/i.test(args.path)) {
        throw new Error('Note path no longer satisfies the security policy.');
      }
      const fd = openSync(check.candidate, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      try { writeFileSync(fd, args.content, 'utf8'); }
      finally { closeSync(fd); }
      return { value: { filename: args.path, bytes: Buffer.byteLength(args.content, 'utf8') },
        summary: `Created a new note: ${basename(check.candidate)}`, simulated: false };
    },
    'network.fetch': async () => ({
      value: { status: 200, body: 'Simulated documentation response; no network connection was made.' },
      summary: 'Simulated GET / → 200; zero network traffic',
      simulated: true
    })
  };
}
