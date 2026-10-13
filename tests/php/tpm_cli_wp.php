<?php
// Same shim as tpm_cli.php, for the WordPress implementation (class-tpm.php).
//   php tests/php/tpm_cli_wp.php /path/to/class-tpm.php < request.json
define( 'ABSPATH', '/' );
function wp_tempnam( $prefix = '' ) { return tempnam( sys_get_temp_dir(), $prefix ); }
function wp_delete_file( $f ) { @unlink( $f ); }
require $argv[1];
$in = json_decode( stream_get_contents( STDIN ), true );
$b  = static fn( $v ) => base64_decode( $v, true );
try {
	switch ( $in['cmd'] ) {
		case 'verify_chain':
			$r = Thessley_Passkey_Tpm::verify_ek_chain( array_map( $b, $in['certs'] ), $in['roots'] );
			echo json_encode( null === $r ? null : array( 'x' => base64_encode( $r['x'] ), 'y' => base64_encode( $r['y'] ), 'manufacturer' => $r['manufacturer'], 'model' => $r['model'] ) );
			break;
		case 'make_credential':
			$r = Thessley_Passkey_Tpm::make_credential( $b( $in['x'] ), $b( $in['y'] ), $b( $in['ak_name'] ), $b( $in['secret'] ) );
			echo json_encode( array( 'credential_blob' => base64_encode( $r['credential_blob'] ), 'secret' => base64_encode( $r['secret'] ) ) );
			break;
		case 'name':
			echo json_encode( array( 'name' => base64_encode( Thessley_Passkey_Tpm::name( $b( $in['public'] ) ) ) ) );
			break;
		case 'verify_certification':
			echo json_encode( array( 'reason' => Thessley_Passkey_Tpm::verify_certification( $b( $in['ak_public'] ), $b( $in['attest'] ), $b( $in['signature'] ), $b( $in['key_public'] ), $in['nonce'], $b( $in['spki'] ) ) ) );
			break;
		default:
			echo json_encode( array( 'error' => 'unknown' ) );
	}
} catch ( Throwable $e ) {
	echo json_encode( array( 'error' => $e->getMessage() ) );
}
