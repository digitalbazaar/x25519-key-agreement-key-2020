mkdir ./dist/esm
cat >dist/esm/index.js <<!EOF
import cjsModule from '../index.js';
export const X25519KeyAgreementKey2020 = cjsModule.X25519KeyAgreementKey2020;
!EOF

cat >dist/esm/package.json <<!EOF
{
  "type": "module"
}
!EOF
