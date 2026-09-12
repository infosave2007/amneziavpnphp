<?php
declare(strict_types=1);
require __DIR__ . '/../../inc/BackupLibrary.php';
$passed = 0; $failed = 0;
function nativeCheck(bool $condition, string $label): void { global $passed,$failed; if ($condition) { $passed++; echo "PASS $label\n"; } else { $failed++; echo "FAIL $label\n"; } }
$defaults = Awg31Parameters::defaults();
$key = base64_encode(str_repeat('h', 32));
$awg = array_merge($defaults, ['protocol_version'=>'3.1','port'=>53131,'server_pub_key'=>$key,'psk_key'=>$key,'subnet_address'=>'10.8.31.0','last_config'=>json_encode(['client_ip'=>'10.8.31.2','client_pub_key'=>$key,'client_priv_key'=>$key,'psk_key'=>$key,'config'=>'raw-native-config'])]);
$entry = ['hostName'=>'203.0.113.9','port'=>22,'userName'=>'root','password'=>'fixture','description'=>'native','containers'=>[['container'=>'amnezia-awg','awg'=>$awg]]];
$write = function(string $name, array $server): string { $path=__DIR__.'/'.$name; file_put_contents($path,json_encode(['Servers/serversList'=>json_encode([$server])])); return $path; };
$parsed = BackupParser::parse($write('native-valid.backup.json',$entry));
$server = $parsed['servers'][0];
nativeCheck($server['install_protocol']==='awg31', 'native amnezia-awg plus 3.1 maps to awg31 identity');
nativeCheck($server['container_name']==='amnezia-awg', 'native observed runtime container preserved');
nativeCheck($server['server_protocols'][0]['slug']==='awg31' && $server['server_protocols'][0]['config_data']['extras']['container_name']==='amnezia-awg', 'native selected binding preserves slug and observed runtime');
nativeCheck($server['clients'][0]['protocol_slug']==='awg31' && $server['clients'][0]['config']==='raw-native-config', 'native client keeps portable slug and raw config');
nativeCheck($server['awg_params']['HeaderProtectionKey']===$defaults['HeaderProtectionKey'], 'native complete normalized AWG31 settings retained');
$bad=$entry; $bad['containers'][0]['container']='unknown-runtime';
try { BackupParser::parse($write('native-contradictory.backup.json',$bad)); nativeCheck(false,'contradictory marker/version rejected'); }
catch (Exception $e) { nativeCheck(str_contains($e->getMessage(),'Contradictory'),'contradictory marker/version rejected'); }
$badVersion=$entry; $badVersion['containers'][0]['awg']['protocol_version']='9.9';
try { BackupParser::parse($write('native-version.backup.json',$badVersion)); nativeCheck(false,'unsupported version rejected'); }
catch (Exception $e) { nativeCheck(str_contains($e->getMessage(),'Unsupported'),'unsupported version rejected'); }
echo "SUMMARY native passed=$passed failed=$failed\n";
exit($failed===0?0:1);
