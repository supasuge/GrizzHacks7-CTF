<?php
libxml_disable_entity_loader(false);
$xmlContent = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlContent, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
$name = $info->name;
$tel = $info->tel;
$email = $info->email;
$password = $info->password;
echo "Sorry, $email is already registered!";
?>
