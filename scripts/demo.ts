#!/usr/bin/env tsx
/**
 * Demo: validate synthetic CAC/PIV-style certificates and show why each is accepted or rejected.
 * Fully self-contained and offline. Everything is generated in memory from throwaway keys.
 *
 *   pnpm --dir reference-impl demo
 */
import { validateCertificateChain, extractEdipi, getThumbprint } from '../reference-impl/src/lib/certs/chain-validator';
import { CrlCache } from '../reference-impl/src/lib/certs/crl-client';
import { createRoot, createIntermediate, createLeaf, createCrl, Issued } from '../reference-impl/src/testing/synthetic-pki';

const DAY = 24 * 3600 * 1000;

async function main() {
  const now = new Date();
  const root = await createRoot();
  const inter = await createIntermediate(root);
  const untrustedRoot = await createRoot('CN=UNTRUSTED ROOT,O=Elsewhere,C=US');

  const crls: Record<string, Uint8Array> = {
    'crl://inter': await createCrl(inter, ['1A0003']),
    'crl://root': await createCrl(root, []),
  };
  const cache = new CrlCache({ fetchImpl: async url => new Response(crls[String(url)] as BodyInit) });
  const crlClient = {
    isRevoked: (c: Issued['cert'], issuer: Issued['cert']) =>
      cache.isRevoked(c, issuer.subject === inter.cert.subject ? 'crl://inter' : 'crl://root', issuer),
  };

  const cases: [string, Issued][] = [
    ['valid card', await createLeaf(inter, { edipi: '1234567890', serial: '1A0001' })],
    ['expired card', await createLeaf(inter, { edipi: '2222222222', serial: '1A0002', notBefore: new Date(now.getTime() - 400 * DAY), notAfter: new Date(now.getTime() - DAY) })],
    ['revoked card (on CRL)', await createLeaf(inter, { edipi: '3333333333', serial: '1A0003' })],
    ['card from untrusted issuer', await createLeaf(untrustedRoot, { edipi: '4444444444', serial: '1A0004' })],
    ['forged card (right issuer name, wrong key)', await createLeaf(inter, { edipi: '5555555555', serial: '1A0005', signingKey: untrustedRoot.keys.privateKey })],
    ['no client-auth usage', await createLeaf(inter, { edipi: '6666666666', serial: '1A0006', clientAuthEku: false })],
  ];

  for (const [label, leaf] of cases) {
    const r = await validateCertificateChain(leaf.cert.toString('pem'), [root.cert], {
      intermediates: [inter.cert.toString('pem')],
      checkRevocation: true,
      crlClient,
    });
    const id = `EDIPI ${extractEdipi(leaf.cert)} sha256:${getThumbprint(leaf.cert).slice(0, 12)}`;
    console.log(`${r.valid ? 'ACCEPT' : 'REJECT'}  ${label.padEnd(42)} ${id}`);
    for (const e of r.errors) console.log(`          - ${e}`);
  }
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
