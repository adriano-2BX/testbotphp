<?php
// Substitua 'senha_super_segura' pela senha que deseja usar.
$senha = 'senha_super_segura'; 
$hash = password_hash($senha, PASSWORD_DEFAULT);

echo "A sua senha encriptada é: " . $hash;
?>
