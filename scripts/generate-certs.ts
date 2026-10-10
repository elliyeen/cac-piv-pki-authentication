#!/usr/bin/env tsx
/**
 * Writes a synthetic PKI to test-fixtures/ for local experiments.
 * Throwaway keys, fictional subjects. No real DoD or federal material.
 *
 *   pnpm --dir reference-impl certs:generate
 */
import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { createRoot, createIntermediate, createLeaf, createCrl } from '../reference-impl/src/testing/synthetic-pki';

const DAY = 24 * 3600 * 1000;
const out = join(__dirname, '..', 'test-fixtures');
const certs = join(out, 'certs');
const crls = join(out, 'crls');

async function main() {
  mkdirSync(certs, { recursive: true });
  mkdirSync(crls, { recursive: true });
  const now = new Date();

  const root = await createRoot();
  const inter = await createIntermediate(root);
  const untrustedRoot = await createRoot('CN=UNTRUSTED ROOT,O=Elsewhere,C=US');

  const valid = await createLeaf(inter, { edipi: '1234567890', serial: '1A0001' });
  const expired = await createLeaf(inter, {
    edipi: '2222222222',
    serial: '1A0002',
    notBefore: new Date(now.getTime() - 400 * DAY),
    notAfter: new Date(now.getTime() - DAY),
  });
  const revoked = await createLeaf(inter, { edipi: '3333333333', serial: '1A0003' });
  const untrusted = await createLeaf(untrustedRoot, { edipi: '4444444444', serial: '1A0004' });

  const files: Record<string, string> = {
    'root-ca.pem': root.cert.toString('pem'),
    'intermediate-ca.pem': inter.cert.toString('pem'),
    'leaf-valid.pem': valid.cert.toString('pem'),
    'leaf-expired.pem': expired.cert.toString('pem'),
    'leaf-revoked.pem': revoked.cert.toString('pem'),
    'leaf-untrusted-issuer.pem': untrusted.cert.toString('pem'),
  };
  for (const [name, pem] of Object.entries(files)) writeFileSync(join(certs, name), pem + '\n');

  writeFileSync(join(crls, 'intermediate-ca.crl'), await createCrl(inter, ['1A0003']));
  writeFileSync(join(crls, 'root-ca.crl'), await createCrl(root, []));

  console.log(`Wrote ${Object.keys(files).length} certificates and 2 CRLs to ${out}`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
