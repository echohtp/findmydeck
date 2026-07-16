// Types for the shared canonical crypto module (crypto/ts/crypto.mjs).
declare module '*/crypto/ts/crypto.mjs' {
  export const KDF_V1: { v: number; alg: string; ops: number; mem: number };
  export function genSalt(): Promise<string>;
  export function toB64(bytes: Uint8Array): Promise<string>;
  export function fromB64(str: string): Promise<Uint8Array>;
  export function deriveKeys(password: string, saltB64: string, kdf?: object): Promise<{
    boxPk: string; signPk: string; boxSk: Uint8Array; signSk: Uint8Array;
  }>;
  export function wipe(...keys: Array<Uint8Array | undefined>): void;
  export function seal(payloadStr: string, boxPkB64: string): Promise<string>;
  export function sealOpen(blobB64: string, boxPkB64: string, boxSk: Uint8Array): Promise<string>;
  export function signCommand(command: object, signSk: Uint8Array): Promise<{ payload: string; sig: string }>;
  export function verifyCommand(payloadStr: string, sigB64: string, signPkB64: string): Promise<boolean>;
}
