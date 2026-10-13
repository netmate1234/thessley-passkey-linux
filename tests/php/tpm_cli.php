<?php
// Test shim: lets the Python tests call the PHP TPM verification (infra/thessley_passkey/src/Tpm.php).
//   php tests/php/tpm_cli.php /path/to/Tpm.php < request.json
require $argv[1];
use Drupal\thessley_passkey\Tpm;
$in = json_decode(stream_get_contents(STDIN), true);
$b = static fn($v) => base64_decode($v, true);
try {
  switch ($in['cmd']) {
    case 'verify_chain':
      $r = Tpm::verifyEkChain(array_map($b, $in['certs']), $in['roots']);
      echo json_encode($r === NULL ? NULL : ['x' => base64_encode($r['x']), 'y' => base64_encode($r['y']), 'manufacturer' => $r['manufacturer'], 'model' => $r['model']]);
      break;
    case 'make_credential':
      $r = Tpm::makeCredential($b($in['x']), $b($in['y']), $b($in['ak_name']), $b($in['secret']));
      echo json_encode(['credential_blob' => base64_encode($r['credential_blob']), 'secret' => base64_encode($r['secret'])]);
      break;
    case 'name':
      echo json_encode(['name' => base64_encode(Tpm::name($b($in['public'])))]);
      break;
    case 'verify_certification':
      echo json_encode(['reason' => Tpm::verifyCertification($b($in['ak_public']), $b($in['attest']), $b($in['signature']), $b($in['key_public']), $in['nonce'], $b($in['spki']))]);
      break;
    default:
      echo json_encode(['error' => 'unknown']);
  }
}
catch (\Throwable $e) {
  echo json_encode(['error' => $e->getMessage()]);
}
