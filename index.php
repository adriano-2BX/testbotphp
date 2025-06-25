<?php
// =================================================================
// Bloco de Configuração e Definição de Funções
// =================================================================

// --- CONFIGURAÇÃO ---
define('DB_URL', 'mysql://root:d21d846891a08dfaa82b@lab_mysql:3306/testbot');
define('AUTH_COOKIE_NAME', 'testbot_auth');

// --- FUNÇÕES GLOBAIS ---

if (!function_exists('get_db_connection')) {
    function get_db_connection() {
        static $conn;
        if ($conn === null || !$conn->ping()) {
            $db_parts = parse_url(DB_URL);
            $db_host = $db_parts['host'] ?? null;
            $db_user = $db_parts['user'] ?? null;
            $db_pass = $db_parts['pass'] ?? null;
            $db_name = isset($db_parts['path']) ? ltrim($db_parts['path'], '/') : null;
            $db_port = $db_parts['port'] ?? 3306;
            mysqli_report(MYSQLI_REPORT_OFF);
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);
            if ($conn->connect_error) { 
                if (function_exists('render_error_page')) {
                     render_error_page("Erro de Conexão", "Não foi possível conectar ao banco de dados.");
                } else {
                    die("Falha crítica ao obter conexão com o banco de dados."); 
                }
                exit;
            }
            $conn->set_charset("utf8mb4");
        }
        return $conn;
    }
}

// --- FUNÇÕES DE AUTENTICAÇÃO BASEADAS EM TOKEN ---

if (!function_exists('login')) {
    function login($email, $password) {
        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($user_data = $result->fetch_assoc()) {
            if (password_verify($password, $user_data['password_hash'])) {
                $token = bin2hex(random_bytes(32));
                $expires = new DateTime('+1 day');
                $expires_sql = $expires->format('Y-m-d H:i:s');

                $update_stmt = $conn->prepare("UPDATE users SET auth_token = ?, token_expires_at = ? WHERE id = ?");
                $update_stmt->bind_param("ssi", $token, $expires_sql, $user_data['id']);
                if ($update_stmt->execute()) {
                    setcookie(AUTH_COOKIE_NAME, $token, [
                        'expires' => $expires->getTimestamp(),
                        'path' => '/',
                        'httponly' => true,
                        'samesite' => 'Lax'
                    ]);
                    return true;
                }
            }
        }
        return false;
    }
}

if (!function_exists('logout')) {
    function logout() {
        if (isset($_COOKIE[AUTH_COOKIE_NAME])) {
            $conn = get_db_connection();
            $token = $_COOKIE[AUTH_COOKIE_NAME];
            $stmt = $conn->prepare("UPDATE users SET auth_token = NULL, token_expires_at = NULL WHERE auth_token = ?");
            $stmt->bind_param("s", $token);
            $stmt->execute();
        }
        setcookie(AUTH_COOKIE_NAME, '', time() - 3600, '/');
        header('Location: index.php?page=login');
        exit;
    }
}

if (!function_exists('get_current_user')) {
    function get_current_user() {
        static $user = null;
        if ($user !== null) return $user;

        if (!isset($_COOKIE[AUTH_COOKIE_NAME])) {
            return null;
        }

        $token = $_COOKIE[AUTH_COOKIE_NAME];
        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT id, name, email, role FROM users WHERE auth_token = ? AND token_expires_at > NOW()");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        return $user;
    }
}

if (!function_exists('is_logged_in')) {
    function is_logged_in() {
        return get_current_user() !== null;
    }
}

if (!function_exists('has_permission')) {
    function has_permission($roles) {
        $user = get_current_user();
        if (!$user) return false;
        return in_array($user['role'], (array)$roles, true);
    }
}

// --- RESTANTE DAS FUNÇÕES (DADOS, RENDERIZAÇÃO, ETC.) ---

// (Copie e cole aqui TODAS as suas outras funções, como seed_initial_templates, get_data, handle_post_requests, e todas as funções de ícones e renderização do seu código original)
// Exemplo:
if (!function_exists('seed_initial_templates')) { function seed_initial_templates() { /* ... a sua lógica ... */ } }
if (!function_exists('get_data')) { function get_data() { /* ... a sua lógica ... */ return []; } }
if (!function_exists('render_header')) { function render_header($title) { ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" /><title><?= htmlspecialchars($title) ?> - TestBot Manager</title><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; overscroll-behavior-y: contain; } .content-scrollable::-webkit-scrollbar { display: none; } .content-scrollable { -ms-overflow-style: none; scrollbar-width: none; } details > summary { list-style: none; } details > summary::-webkit-details-marker { display: none; }</style></head><body class="bg-gray-100 text-gray-900 min-h-screen antialiased"><?php } }
if (!function_exists('render_footer')) { function render_footer() { ?></body></html><?php } }
if (!function_exists('render_flash_message')) { function render_flash_message() { if (session_status() === PHP_SESSION_NONE) session_start(); if (isset($_SESSION['flash_message'])) { $flash = $_SESSION['flash_message']; $colors = [ 'success' => 'bg-green-100 border-green-500 text-green-700', 'error' => 'bg-red-100 border-red-500 text-red-700', 'info' => 'bg-blue-100 border-blue-500 text-blue-700' ]; $colorClass = $colors[$flash['type']] ?? $colors['info']; echo '<div class="' . $colorClass . ' border-l-4 p-4 mb-4 rounded-r-lg" role="alert"><p>' . htmlspecialchars($flash['message']) . '</p></div>'; unset($_SESSION['flash_message']); } } }
if (!function_exists('render_app_layout')) { function render_app_layout($page, callable $content_renderer, $all_data) { $user = get_current_user(); if (!$user) { logout(); return; } $pageTitles = ['dashboard' => "Dashboard", 'test-management' => "Gerir Testes", 'user-management' => "Gerir Utilizadores", 'reports' => "Relatórios", 'client-management' => "Gerir Clientes", 'project-management' => "Gerir Projetos", 'test-guidelines' => "Orientações de Teste", 'custom-templates' => "Modelos Personalizados"]; $title = $pageTitles[$page] ?? 'Detalhes'; render_header($title); $navItems = [ 'admin' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Clientes", 'path' => "client-management", 'icon' => BuildingIcon()],['name' => "Projetos", 'path' => "project-management", 'icon' => FolderIcon()],['name' => "Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Utilizadores", 'path' => "user-management", 'icon' => UsersIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Modelos", 'path' => "custom-templates", 'icon' => BeakerIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'tester' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Meus Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'client' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], ]; $userNav = $navItems[$user['role']] ?? []; ?> <div class="h-screen w-screen flex flex-col sm:flex-row bg-gray-100"> <div class="hidden sm:flex flex-col w-64 bg-white border-r border-gray-200 p-4"> <h1 class="text-2xl font-bold text-cyan-600 mb-10 px-2">TestBot</h1> <nav class="flex-1 space-y-2"><?php foreach ($userNav as $item): $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="w-full flex items-center gap-3 text-left py-2.5 px-4 rounded-lg transition-colors text-base font-semibold <?= $isActive ? 'bg-cyan-500 text-white shadow-sm' : 'text-gray-600 hover:bg-gray-100' ?>"><?= HomeIcon('class="w-5 h-5"') ?><?= htmlspecialchars($item['name']) ?></a><?php endforeach; ?></nav> <div class="pt-6 border-t border-gray-200"><p class="text-sm font-semibold text-gray-800"><?= htmlspecialchars($user['name']) ?></p><p class="text-xs text-gray-500 capitalize"><?= htmlspecialchars($user['role']) ?></p></div> </div> <div class="flex-1 flex flex-col overflow-hidden"> <header class="bg-white/80 backdrop-blur-lg border-b border-gray-200 w-full z-10"><div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8"><div class="flex items-center justify-between h-16"><h1 class="text-lg font-bold text-gray-800"><?= htmlspecialchars($title) ?></h1><a href="index.php?page=logout" class="hidden sm:flex items-center gap-2 text-sm font-semibold text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-5 h-5"') ?>Sair</a></div></div></header> <main class="flex-1 overflow-y-auto content-scrollable p-4 sm:p-6 pb-24 sm:pb-6"><?php render_flash_message(); $content_renderer($all_data); ?></main> <nav class="sm:hidden fixed bottom-0 left-0 right-0 bg-white/80 backdrop-blur-lg border-t border-gray-200 z-20"><div class="flex justify-around items-center h-16"><?php foreach ($userNav as $item): if(count($userNav) > 4 && $item['name'] === 'Orientações') continue; $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="flex flex-col items-center justify-center w-full h-full transition-colors <?= $isActive ? 'text-cyan-500' : 'text-gray-500 hover:text-cyan-500' ?>"><?= HomeIcon('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium"><?= htmlspecialchars($item['name']) ?></span></a><?php endforeach; ?><a href="index.php?page=logout" class="flex flex-col items-center justify-center w-full h-full text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium">Sair</span></a></div></nav> </div> </div> <?php render_footer(); } }
if (!function_exists('render_login_page')) { function render_login_page() { render_header('Login'); ?><div class="min-h-screen flex items-center justify-center bg-gray-100 px-4"><div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm"><h1 class="text-3xl font-bold text-gray-800 text-center mb-2">TestBot</h1><p class="text-center text-gray-500 mb-8">Manager Login</p><?php render_flash_message(); ?><form method="POST" action="index.php"><input type="hidden" name="action" value="login"><div class="mb-4"><label for="email" class="text-sm font-bold text-gray-600 mb-1 block">Email</label><input id="email" name="email" type="email" autocomplete="username" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><div class="mb-6"><label for="password" class="text-sm font-bold text-gray-600 mb-1 block">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg hover:bg-cyan-600 transition duration-200 font-bold">Entrar</button></form></div></div><?php render_footer(); } }
if (!function_exists('render_dashboard_page')) { function render_dashboard_page($data) { $user = get_current_user(); if (!$user) { logout(); return; } $firstName = explode(' ', $user['name'])[0]; ?> <div class="space-y-6"><h2 class="text-2xl font-bold text-gray-800">Olá, <?= htmlspecialchars($firstName) ?>!</h2></div> <?php } }
// Adicione as outras funções de renderização aqui...
if (!function_exists('render_error_page')) { function render_error_page($title, $message) { render_header("Erro"); echo "<h1>$title</h1><p>$message</p>"; render_footer(); } }

// =================================================================
// Bloco de Execução Principal
// =================================================================

// Lida com o POST do formulário de login antes de qualquer outra coisa
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (($_POST['action'] ?? '') === 'login') {
        if (login($_POST['email'] ?? '', $_POST['password'] ?? '')) {
            header('Location: index.php?page=dashboard');
        } else {
            // Usa sessões apenas para a mensagem de erro flash
            if (session_status() === PHP_SESSION_NONE) session_start();
            $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Credenciais inválidas.'];
            header('Location: index.php?page=login');
        }
        exit;
    }
}

// Roteamento para páginas GET
$page = $_GET['page'] ?? 'login';

$pages = [
    'dashboard' => ['renderer' => 'render_dashboard_page', 'roles' => ['admin', 'tester', 'client']],
    // Adicione as outras páginas aqui
];

if ($page === 'logout') {
    logout();
}

// Se o utilizador não estiver logado, a única página que ele pode ver é a de login.
if (!is_logged_in()) {
    render_login_page();
    exit;
}

// Se o utilizador está logado...
if (isset($pages[$page]) && has_permission($pages[$page]['roles'])) {
    // Caminho feliz: renderiza a página solicitada
    $renderer = $pages[$page]['renderer'];
    $all_data = get_data();
    render_app_layout($page, $renderer, $all_data);
} else {
    // Se a página for inválida ou sem permissão, redireciona para o dashboard
    header('Location: index.php?page=dashboard');
    exit;
}

?>
