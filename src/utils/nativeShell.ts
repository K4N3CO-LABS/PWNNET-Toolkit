import { registerPlugin } from '@capacitor/core';
import { Capacitor } from '@capacitor/core';

export interface NativeShellPlugin {
  execute(options: { command: string }): Promise<{ output: string, exitCode: number }>;
}

export const NativeShell = registerPlugin<NativeShellPlugin>('NativeShell');

export const isNative = Capacitor.isNativePlatform();
