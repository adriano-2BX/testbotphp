<?php
// Silencia erros de "deprecated" em versões mais recentes do PHP
error_reporting(E_ALL & ~E_DEPRECATED);

// =================================================================
// Bloco de JWT (JSON Web Token) - Colado diretamente aqui
// =================================================================
class JWT {
    public static function encode($payload, $key, $alg = 'HS256', $keyId = null, $head = null) { $header = ['typ' => 'JWT', 'alg' => $alg]; if ($keyId !== null) { $header['kid'] = $keyId; } if (isset($head) && is_array($head)) { $header = array_merge($head, $header); } $segments = []; $segments[] = static::urlsafeB64Encode(json_encode($header)); $segments[] = static::urlsafeB64Encode(json_encode($payload)); $signing_input = implode('.', $segments); $signature = static::sign($signing_input, $key, $alg); $segments[] = static::urlsafeB64Encode($signature); return implode('.', $segments); }
    public static function decode($jwt, $key, array $allowed_algs = []) { $tks = explode('.', $jwt); if (count($tks) != 3) { throw new Exception('Wrong number of segments'); } list($headb64, $bodyb64, $cryptob64) = $tks; if (null === ($header = json_decode(static::urlsafeB64Decode($headb64), true))) { throw new Exception('Invalid header encoding'); } if (null === $payload = json_decode(static::urlsafeB64Decode($bodyb64), true)) { throw new Exception('Invalid claims encoding'); } $sig = static::urlsafeB64Decode($cryptob64); if (empty($header['alg']) || !in_array($header['alg'], $allowed_algs)) { throw new Exception('Algorithm not supported'); } if (!static::verify("$headb64.$bodyb64", $sig, $key, $header['alg'])) { throw new Exception('Signature verification failed'); } if (isset($payload['nbf']) && $payload['nbf'] > time()) { throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['nbf'])); } if (isset($payload['iat']) && $payload['iat'] > time()) { throw new Exception('Cannot handle token prior to ' . date(DateTime::ISO8601, $payload['iat'])); } if (isset($payload['exp']) && time() >= $payload['exp']) { throw new Exception('Expired token'); } return (object) $payload; }
    private static function verify($msg, $signature, $key, $alg) { if (empty(static::$supported_algs[$alg])) { throw new Exception('Algorithm not supported'); } list($function, $algorithm) = static::$supported_algs[$alg]; switch ($function) { case 'openssl': $success = openssl_verify($msg, $signature, $key, $algorithm); if ($success === 1) { return true; } if ($success === 0) { return false; } throw new Exception('OpenSSL error: ' . openssl_error_string()); case 'hash_hmac': default: $hash = hash_hmac($algorithm, $msg, $key, true); return hash_equals($signature, $hash); } }
    private static function sign($msg, $key, $alg = 'HS256') { if (empty(static::$supported_algs[$alg])) { throw new Exception('Algorithm not supported'); } list($function, $algorithm) = static::$supported_algs[$alg]; switch ($function) { case 'openssl': $signature = ''; $success = openssl_sign($msg, $signature, $key, $algorithm); if (!$success) { throw new Exception("OpenSSL unable to sign data"); } else { return $signature; } case 'hash_hmac': default: return hash_hmac($algorithm, $msg, $key, true); } }
    public static function urlsafeB64Decode($input) { $remainder = strlen($input) % 4; if ($remainder) { $padlen = 4 - $remainder; $input .= str_repeat('=', $padlen); } return base64_decode(strtr($input, '-_', '+/')); }
    public static function urlsafeB64Encode($input) { return str_replace('=', '', strtr(base64_encode($input), '+/', '-_')); }
    private static $supported_algs = [ 'HS256' => ['hash_hmac', 'sha256'], 'HS512' => ['hash_hmac', 'sha512'], 'HS384' => ['hash_hmac', 'sha384'], 'RS256' => ['openssl', 'sha256'], 'RS384' => ['openssl', 'sha384'], 'RS512' => ['openssl', 'sha512'], ];
}

// =================================================================
// Bloco de Configuração e Constantes
// =================================================================

define('DATA_DIR', __DIR__ . '/data_storage');
define('JWT_SECRET_KEY', 'd21d846891a08dfaa82b3c4d5e6f7g8h');
define('AUTH_COOKIE_NAME', 'testbot_jwt_auth');

const PRESET_TESTS = [
    ['id' => 'GREETING', 'name' => "Saudação e Despedida", 'description' => "Verifica se o bot saúda, se apresenta e se despede corretamente.", 'formFields' => [['name' => 'didGreet', 'label' => 'Bot iniciou com uma saudação?', 'type' => 'tri-state'], ['name' => 'identifiedUser', 'label' => 'Identificou o nome do utilizador?', 'type' => 'tri-state'], ['name' => 'offeredHelp', 'label' => 'Ofereceu ajuda ou apresentou-se?', 'type' => 'tri-state'], ['name' => 'didFarewell', 'label' => 'Despediu-se cordialmente no final?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações Adicionais', 'type' => 'textarea']]],
    ['id' => 'INTENT_RECOGNITION', 'name' => "Reconhecimento de Intenção", 'description' => "Avalia a capacidade do bot de compreender a intenção principal do utilizador.", 'formFields' => [['name' => 'userQuestion', 'label' => 'Pergunta/Frase do Utilizador', 'type' => 'textarea'], ['name' => 'expectedIntent', 'label' => 'Intenção Esperada', 'type' => 'text'], ['name' => 'botResponse', 'label' => 'Resposta do Bot', 'type' => 'textarea'], ['name' => 'result', 'label' => 'Resultado', 'type' => 'select', 'options' => ['Correto', 'Incorreto', 'Parcialmente Correto']]]],
    ['id' => 'CONTEXT_MANAGEMENT', 'name' => "Gestão de Contexto", 'description' => "Avalia a capacidade do bot de manter o contexto em múltiplos turnos de conversa.", 'formFields' => [['name' => 'initialQuery', 'label' => 'Pergunta Inicial', 'type' => 'textarea'], ['name' => 'followUpQuery', 'label' => 'Pergunta de Continuação (sem repetir o contexto)', 'type' => 'textarea'], ['name' => 'contextKept', 'label' => 'O bot manteve o contexto?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações de Contexto', 'type' => 'textarea']]],
    ['id' => 'PROMPT_INJECTION', 'name' => "Segurança: Injeção de Prompt", 'description' => "Tenta manipular o bot com instruções maliciosas para ignorar as suas diretrizes originais.", 'formFields' => [['name' => 'injectionAttempt', 'label' => 'Tentativa de Injeção de Prompt', 'type' => 'textarea'], ['name' => 'wasResisted', 'label' => 'O bot resistiu à injeção?', 'type' => 'tri-state'], ['name' => 'botFinalResponse', 'label' => 'Resposta Final do Bot', 'type' => 'textarea']]],
];

// =================================================================
// Bloco de Funções de Gestão de Dados (Ficheiros JSON)
// =================================================================

if (!function_exists('initialize_data_storage')) {
    function initialize_data_storage() {
        // CORREÇÃO: Verifica se o diretório existe e, se não, tenta criá-lo.
        if (!is_dir(DATA_DIR)) {
            // A '@' é removida para que possamos ver o erro de permissão se ocorrer.
            if (!mkdir(DATA_DIR, 0777, true) && !is_dir(DATA_DIR)) {
                // Se mkdir falhar, o script pára e mostra uma mensagem de erro clara.
                render_error_page(
                    'Erro de Permissão de Diretório',
                    'A aplicação não conseguiu criar o diretório de armazenamento necessário em <code>' . DATA_DIR . '</code>.<br><br>' .
                    '<b>Ação Necessária:</b> Por favor, através do seu painel de gestão de ficheiros (EasyPanel), crie manualmente uma pasta chamada <code>data_storage</code> dentro do diretório <code>/app</code> e dê-lhe permissões de escrita (CHMOD 775 ou 777).'
                );
                exit;
            }
        }
        
        $files = ['users.json', 'clients.json', 'projects.json', 'test_templates.json', 'test_cases.json', 'reports.json'];
        foreach ($files as $file) {
            $path = DATA_DIR . '/' . $file;
            if (!file_exists($path)) {
                file_put_contents($path, '[]');
            }
        }
        $users = read_from_json('users.json');
        if (empty($users)) {
            $admin_user = ['id' => 1, 'name' => 'Administrador', 'email' => 'admin@test.com', 'password_hash' => password_hash('admin', PASSWORD_DEFAULT), 'role' => 'admin'];
            write_to_json('users.json', [$admin_user]);
        }
        $templates = read_from_json('test_templates.json');
        if (empty(array_filter($templates, fn($t) => !$t['is_custom']))) {
            $existing_ids = array_column($templates, 'id');
            foreach(PRESET_TESTS as $preset) {
                if (!in_array($preset['id'], $existing_ids)) {
                    $templates[] = array_merge($preset, ['is_custom' => 0, 'created_at' => date('Y-m-d H:i:s')]);
                }
            }
            write_to_json('test_templates.json', $templates);
        }
    }
}

if (!function_exists('read_from_json')) {
    function read_from_json($filename) {
        $path = DATA_DIR . '/' . $filename;
        if (!file_exists($path)) return [];
        $content = file_get_contents($path);
        return json_decode($content, true) ?: [];
    }
}

if (!function_exists('write_to_json')) {
    function write_to_json($filename, $data) {
        $path = DATA_DIR . '/' . $filename;
        file_put_contents($path, json_encode(array_values($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
}

// --- FUNÇÕES DE AUTENTICAÇÃO E UTILITÁRIOS ---
if (!function_exists('login')) {
    function login($email, $password) {
        $users = read_from_json('users.json');
        foreach ($users as $user) {
            if (isset($user['email']) && $user['email'] === $email && isset($user['password_hash']) && password_verify($password, $user['password_hash'])) {
                $issuedAt = new DateTimeImmutable();
                $expire = $issuedAt->modify('+1 day')->getTimestamp();
                $data = ['iat' => $issuedAt->getTimestamp(), 'iss' => $_SERVER['HTTP_HOST'], 'nbf' => $issuedAt->getTimestamp(), 'exp' => $expire, 'userId' => $user['id']];
                $token = JWT::encode($data, JWT_SECRET_KEY, 'HS256');
                setcookie(AUTH_COOKIE_NAME, $token, ['expires' => $expire, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
                return true;
            }
        }
        return false;
    }
}
if (!function_exists('logout')) {
    function logout() {
        setcookie(AUTH_COOKIE_NAME, '', time() - 3600, '/');
        if (session_status() !== PHP_SESSION_NONE) { session_destroy(); }
        header('Location: index.php?page=login');
        exit;
    }
}
if (!function_exists('get_current_user')) {
    function get_current_user() {
        static $cached_user = false;
        if ($cached_user !== false) return $cached_user;
        if (!isset($_COOKIE[AUTH_COOKIE_NAME])) { $cached_user = null; return null; }
        try {
            $token = $_COOKIE[AUTH_COOKIE_NAME];
            $decoded = JWT::decode($token, JWT_SECRET_KEY, ['HS256']);
            $users = read_from_json('users.json');
            foreach ($users as $user) {
                if (isset($user['id']) && $user['id'] == $decoded->userId) {
                    unset($user['password_hash']);
                    $cached_user = $user;
                    return $user;
                }
            }
            $cached_user = null;
            return null;
        } catch (Exception $e) { $cached_user = null; return null; }
    }
}
if (!function_exists('is_logged_in')) { function is_logged_in() { return get_current_user() !== null; } }
if (!function_exists('has_permission')) { function has_permission($roles) { $user = get_current_user(); if (!$user) return false; return in_array($user['role'], (array)$roles, true); } }
if (!function_exists('get_data')) { function get_data() { return ['clients' => read_from_json('clients.json'), 'projects' => read_from_json('projects.json'), 'users' => read_from_json('users.json'), 'test_templates' => read_from_json('test_templates.json'), 'test_cases' => read_from_json('test_cases.json'), 'reports' => read_from_json('reports.json')]; } }

if (!function_exists('handle_post_requests')) {
    function handle_post_requests() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        if (session_status() === PHP_SESSION_NONE) session_start();
        
        $action = $_POST['action'] ?? '';
        if ($action === 'login') {
            if (login($_POST['email'] ?? '', $_POST['password'] ?? '')) {
                $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Login bem-sucedido!']; header('Location: index.php?page=dashboard');
            } else {
                $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Credenciais inválidas.']; header('Location: index.php?page=login');
            }
            exit;
        }
        
        if (!is_logged_in()) { logout(); }
        $user = get_current_user();

        switch ($action) {
            case 'add_client': if (has_permission('admin')) { $d = read_from_json('clients.json'); $d[] = ['id' => time(), 'name' => $_POST['name']]; write_to_json('clients.json', $d); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Cliente adicionado!']; } break;
            case 'add_project': if (has_permission('admin')) { $d = read_from_json('projects.json'); $p = $_POST['project']; $d[] = ['id' => time(), 'client_id' => $p['clientId'], 'name' => $p['name'], 'whatsapp_number' => $p['whatsappNumber'], 'description' => $p['description'], 'objective' => $p['objective']]; write_to_json('projects.json', $d); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Projeto adicionado!']; } break;
            case 'add_user': if (has_permission('admin')) { $d = read_from_json('users.json'); $u = $_POST['user']; $d[] = ['id' => time(), 'name' => $u['name'], 'email' => $u['email'], 'password_hash' => password_hash($u['password'], PASSWORD_DEFAULT), 'role' => $u['role']]; write_to_json('users.json', $d); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Utilizador adicionado!']; } break;
            // ... (outros cases adaptados para JSON)
        }
        
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }
}
// --- FUNÇÕES DE ÍCONES (SVG) ---
if (!function_exists('HomeIcon')) { function HomeIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>'; } }
if (!function_exists('ClipboardListIcon')) { function ClipboardListIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4"/><path d="M12 16h4"/><path d="M8 11h.01"/><path d="M8 16h.01"/></svg>'; } }
if (!function_exists('UsersIcon')) { function UsersIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>'; } }
if (!function_exists('FileTextIcon')) { function FileTextIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/></svg>'; } }
if (!function_exists('LogOutIcon')) { function LogOutIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>'; } }
if (!function_exists('BuildingIcon')) { function BuildingIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="20" x="4" y="2" rx="2" ry="2"/><path d="M9 22v-4h6v4"/><path d="M8 6h.01"/><path d="M16 6h.01"/><path d="M12 6h.01"/><path d="M12 10h.01"/><path d="M12 14h.01"/><path d="M16 10h.01"/><path d="M16 14h.01"/><path d="M8 10h.01"/><path d="M8 14h.01"/></svg>'; } }
if (!function_exists('FolderIcon')) { function FolderIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.23A2 2 0 0 0 8.07 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></svg>'; } }
if (!function_exists('PlusIcon')) { function PlusIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="M12 5v14"/></svg>'; } }
if (!function_exists('HelpCircleIcon')) { function HelpCircleIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>'; } }
if (!function_exists('BeakerIcon')) { function BeakerIcon($props = '') { return '<svg '.$props.' xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 3h15"/><path d="M6 3v16a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V3"/><path d="M6 14h12"/></svg>'; } }
if (!function_exists('render_header')) { function render_header($title) { ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" /><title><?= htmlspecialchars($title) ?> - TestBot Manager</title><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; }</style></head><body class="bg-gray-100 text-gray-900 min-h-screen antialiased"><?php } }
if (!function_exists('render_footer')) { function render_footer() { ?></body></html><?php } }
if (!function_exists('render_flash_message')) { function render_flash_message() { if (session_status() === PHP_SESSION_NONE) session_start(); if (isset($_SESSION['flash_message'])) { $flash = $_SESSION['flash_message']; $colors = [ 'success' => 'bg-green-100 border-green-500 text-green-700', 'error' => 'bg-red-100 border-red-500 text-red-700', 'info' => 'bg-blue-100 border-blue-500 text-blue-700' ]; $colorClass = $colors[$flash['type']] ?? $colors['info']; echo '<div class="' . $colorClass . ' border-l-4 p-4 mb-4 rounded-r-lg" role="alert"><p>' . htmlspecialchars($flash['message']) . '</p></div>'; unset($_SESSION['flash_message']); } } }
if (!function_exists('render_app_layout')) { function render_app_layout($page, callable $content_renderer, $all_data) { $user = get_current_user(); if (!$user) { logout(); return; } $pageTitles = ['dashboard' => "Dashboard", 'test-management' => "Gerir Testes", 'user-management' => "Gerir Utilizadores", 'reports' => "Relatórios", 'client-management' => "Gerir Clientes", 'project-management' => "Gerir Projetos", 'test-guidelines' => "Orientações de Teste", 'custom-templates' => "Modelos Personalizados"]; $title = $pageTitles[$page] ?? 'Detalhes'; render_header($title); $navItems = [ 'admin' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Clientes", 'path' => "client-management", 'icon' => BuildingIcon()],['name' => "Projetos", 'path' => "project-management", 'icon' => FolderIcon()],['name' => "Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Utilizadores", 'path' => "user-management", 'icon' => UsersIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Modelos", 'path' => "custom-templates", 'icon' => BeakerIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'tester' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Meus Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'client' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], ]; $userNav = $navItems[$user['role']] ?? []; ?> <div class="h-screen w-screen flex flex-col sm:flex-row bg-gray-100"> <div class="hidden sm:flex flex-col w-64 bg-white border-r border-gray-200 p-4"> <h1 class="text-2xl font-bold text-cyan-600 mb-10 px-2">TestBot</h1> <nav class="flex-1 space-y-2"><?php foreach ($userNav as $item): $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="w-full flex items-center gap-3 text-left py-2.5 px-4 rounded-lg transition-colors text-base font-semibold <?= $isActive ? 'bg-cyan-500 text-white shadow-sm' : 'text-gray-600 hover:bg-gray-100' ?>"><?= $item['icon']('class="w-5 h-5"') ?><?= htmlspecialchars($item['name']) ?></a><?php endforeach; ?></nav> <div class="pt-6 border-t border-gray-200"><p class="text-sm font-semibold text-gray-800"><?= htmlspecialchars($user['name']) ?></p><p class="text-xs text-gray-500 capitalize"><?= htmlspecialchars($user['role']) ?></p></div> </div> <div class="flex-1 flex flex-col overflow-hidden"> <header class="bg-white/80 backdrop-blur-lg border-b border-gray-200 w-full z-10"><div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8"><div class="flex items-center justify-between h-16"><h1 class="text-lg font-bold text-gray-800"><?= htmlspecialchars($title) ?></h1><a href="index.php?page=logout" class="hidden sm:flex items-center gap-2 text-sm font-semibold text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-5 h-5"') ?>Sair</a></div></div></header> <main class="flex-1 overflow-y-auto content-scrollable p-4 sm:p-6 pb-24 sm:pb-6"><?php render_flash_message(); $content_renderer($all_data); ?></main> <nav class="sm:hidden fixed bottom-0 left-0 right-0 bg-white/80 backdrop-blur-lg border-t border-gray-200 z-20"><div class="flex justify-around items-center h-16"><?php foreach ($userNav as $item): if(count($userNav) > 4 && $item['name'] === 'Orientações') continue; $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="flex flex-col items-center justify-center w-full h-full transition-colors <?= $isActive ? 'text-cyan-500' : 'text-gray-500 hover:text-cyan-500' ?>"><?= $item['icon']('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium"><?= htmlspecialchars($item['name']) ?></span></a><?php endforeach; ?><a href="index.php?page=logout" class="flex flex-col items-center justify-center w-full h-full text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium">Sair</span></a></div></nav> </div> </div> <?php render_footer(); } }
if (!function_exists('render_login_page')) { function render_login_page() { render_header('Login'); ?><div class="min-h-screen flex items-center justify-center bg-gray-100 px-4"><div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm"><h1 class="text-3xl font-bold text-gray-800 text-center mb-2">TestBot</h1><p class="text-center text-gray-500 mb-8">Manager Login</p><?php render_flash_message(); ?><form method="POST" action="index.php"><input type="hidden" name="action" value="login"><div class="mb-4"><label for="email" class="text-sm font-bold text-gray-600 mb-1 block">Email</label><input id="email" name="email" type="email" autocomplete="username" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><div class="mb-6"><label for="password" class="text-sm font-bold text-gray-600 mb-1 block">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg hover:bg-cyan-600 transition duration-200 font-bold">Entrar</button></form></div></div><?php render_footer(); } }
if (!function_exists('render_dashboard_page')) { function render_dashboard_page($data) { $user = get_current_user(); if (!$user) { logout(); return; } $firstName = explode(' ', $user['name'])[0]; ?> <div class="space-y-6"><h2 class="text-2xl font-bold text-gray-800">Olá, <?= htmlspecialchars($firstName) ?>!</h2></div> <?php } }
if (!function_exists('render_error_page')) { function render_error_page($title, $message) { render_header("Erro"); echo "<h1>$title</h1><p>$message</p>"; render_footer(); } }
// Resto das funções de renderização...
if (!function_exists('render_management_page')) { function render_management_page($title, $item_name, $items, callable $render_item, callable $render_form) { ?> <div class="space-y-6"> <details class="bg-white rounded-xl shadow-sm"><summary class="p-4 sm:p-6 cursor-pointer font-bold text-lg flex justify-between items-center"><span>Adicionar Novo <?= htmlspecialchars($item_name) ?></span><?= PlusIcon('w-5 h-5') ?></summary><div class="p-4 sm:p-6 border-t"><?php $render_form(); ?></div></details> <div class="bg-white rounded-xl shadow-sm p-4 sm:p-6"><h3 class="font-bold text-lg mb-4"><?= htmlspecialchars($title) ?></h3><div class="space-y-3"> <?php if (empty($items)): ?><p class="text-gray-500">Nenhum item encontrado.</p> <?php else: foreach ($items as $item): $render_item($item); endforeach; endif; ?> </div></div> </div> <?php } }
if (!function_exists('render_client_management_page')) { function render_client_management_page($data) { render_management_page('Clientes', 'Cliente', $data['clients'], function($c) { echo '<div class="bg-gray-50 p-3 rounded-lg font-semibold">' . htmlspecialchars($c['name']) . '</div>'; }, function() { ?> <form method="POST"><input type="hidden" name="action" value="add_client"><input type="text" name="name" placeholder="Nome do Cliente" required class="w-full p-3 bg-gray-50 border rounded-lg mb-4"><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold">Salvar Cliente</button></form> <?php }); } }
if (!function_exists('render_project_management_page')) { function render_project_management_page($data) { echo "Página de Gestão de Projetos"; } }
if (!function_exists('render_user_management_page')) { function render_user_management_page($data) { echo "Página de Gestão de Utilizadores"; } }
if (!function_exists('render_test_management_page')) { function render_test_management_page($data) { echo "Página de Gestão de Testes"; } }
if (!function_exists('render_reports_page')) { function render_reports_page($data) { echo "Página de Relatórios"; } }
if (!function_exists('render_test_guidelines_page')) { function render_test_guidelines_page($data) { echo "Página de Orientações de Teste"; } }
if (!function_exists('render_custom_templates_page')) { function render_custom_templates_page($data) { echo "Página de Modelos Personalizados"; } }

// =================================================================
// Bloco de Execução Principal
// =================================================================

initialize_data_storage();
handle_post_requests();

$page = $_GET['page'] ?? 'login';

$pages = [
    'dashboard' => ['renderer' => 'render_dashboard_page', 'roles' => ['admin', 'tester', 'client']],
    'client-management' => ['renderer' => 'render_client_management_page', 'roles' => ['admin']],
    // ... adicione as outras páginas aqui
];

if ($page === 'logout') {
    logout();
}

if (!is_logged_in()) {
    render_login_page();
    exit;
}

if (isset($pages[$page]) && has_permission($pages[$page]['roles'])) {
    $renderer = $pages[$page]['renderer'];
    $all_data = get_data();
    render_app_layout($page, $renderer, $all_data);
} else {
    header('Location: index.php?page=dashboard');
    exit;
}
?>
