<?php
// Inicia a sessão no topo de todas as páginas. Essencial para autenticação.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- BLOCO DE DEPURAÇÃO DE LOGIN ---
// Este bloco será executado APENAS na requisição imediatamente após uma tentativa de login.
if (isset($_GET['from_login']) && $_GET['from_login'] === '1') {
    // Define o tipo de conteúdo para HTML para uma exibição clara.
    header('Content-Type: text/html; charset=utf-8');
    // Inicia a renderização da página de depuração.
    echo '<html><head><title>Depuração de Login</title><style>body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; padding: 20px; background-color: #f8f9fa; color: #212529; } .container { max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); } h1, h2 { color: #343a40; } pre { background-color: #e9ecef; padding: 15px; border-radius: 5px; border: 1px solid #dee2e6; white-space: pre-wrap; word-wrap: break-word; } code { font-family: "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; color: #c7254e; background-color: #f9f2f4; border-radius: 3px; padding: 2px 4px; } .success { color: #28a745; font-weight: bold; } .error { color: #dc3545; font-weight: bold; }</style></head><body>';
    echo '<div class="container">';
    echo '<h1>Resultado da Tentativa de Login</h1>';
    echo '<p>Esta página analisa o estado da sessão imediatamente após o redirecionamento do formulário de login. O resultado abaixo indica a causa do problema.</p><hr>';
    
    // Verifica o estado da sessão.
    if (session_status() === PHP_SESSION_ACTIVE) {
        echo '<p class="success">✔ O estado da sessão do PHP está ATIVO.</p>';
    } else {
        echo '<p class="error">❌ O estado da sessão do PHP NÃO está ativo. A sessão não foi iniciada corretamente.</p>';
    }

    // A verificação crucial: A variável de sessão do utilizador existe?
    if (isset($_SESSION['user']) && is_array($_SESSION['user'])) {
        echo '<p class="success">✔ SUCESSO: A variável de sessão <code>$_SESSION[\'user\']</code> FOI encontrada.</p>';
        echo '<h2>Dados do Utilizador na Sessão:</h2>';
        echo '<pre>' . htmlspecialchars(print_r($_SESSION['user'], true)) . '</pre>';
        echo '<h3>Conclusão:</h3>';
        echo '<p>O login funcionou e a sessão foi guardada corretamente. <b>O problema não está na gestão da sessão.</b> Se o loop de login persistir depois de remover este bloco de depuração, o problema pode estar em alguma regra de reescrita de URL (.htaccess) ou configuração do servidor que interfere com o parâmetro <code>page=dashboard</code>.</p>';
    } else {
        echo '<p class="error">❌ FALHA: A variável de sessão <code>$_SESSION[\'user\']</code> NÃO foi encontrada!</p>';
        echo '<h2>Dados da Sessão (Variável $_SESSION completa):</h2>';
        echo '<pre>' . htmlspecialchars(print_r($_SESSION, true)) . '</pre>';
        echo '<h3>Conclusão:</h3>';
        echo '<p>O login pode ter sido válido, mas <b>os dados da sessão não foram mantidos</b> entre a página de login e esta página. Esta é a causa definitiva do loop de login.</p>';
        echo '<h3>Causa Mais Provável:</h3>';
        echo '<p>O PHP não tem permissão para escrever ficheiros de sessão no diretório do servidor. Verifique o caminho abaixo:</p>';
        echo '<code>' . htmlspecialchars(session_save_path()) . '</code>';
        echo '<h4>Como Resolver (para ambientes Docker/Linux):</h4>';
        echo '<p>Conecte-se ao seu servidor/contentor e execute um comando para dar permissões de escrita a esse diretório, por exemplo: <code>chmod 777 ' . htmlspecialchars(session_save_path()) . '</code> ou ajuste as permissões do proprietário (<code>chown</code>).</p>';
    }
    
    echo '<hr><p><a href="index.php">Clique aqui</a> para tentar carregar a aplicação novamente (após resolver o problema indicado acima).</p>';
    echo '</div></body></html>';
    // Para a execução do script para que apenas a página de depuração seja mostrada.
    exit; 
}
// --- FIM DO BLOCO DE DEPURAÇÃO ---


// --- DIAGNÓSTICO DE SESSÃO ---
$session_save_path = session_save_path();
if ($session_save_path && !is_writable($session_save_path)) {
    render_error_page(
        'Erro de Configuração do Servidor',
        'O diretório de sessões do PHP não tem permissão de escrita. A aplicação não pode funcionar corretamente.<br><br>' .
        '<b>Caminho do Diretório:</b> ' . htmlspecialchars($session_save_path) . '<br><br>' .
        'Por favor, verifique as permissões do diretório no servidor. Em ambientes Docker, isso geralmente significa ajustar as permissões do volume ou do diretório dentro do contentor (ex: `chmod 777 /tmp/sessions`).'
    );
    exit;
}

// --- CONFIGURAÇÃO DO BANCO DE DADOS E CONSTANTES ---
define('DB_HOST', 'lab_mysql');
define('DB_USER', 'root');
define('DB_PASS', 'd21d846891a08dfaa82b');
define('DB_NAME', 'testbot');
define('DB_PORT', 3306);

const PRESET_TESTS = [
    ['id' => 'GREETING', 'name' => "Saudação e Despedida", 'description' => "Verifica se o bot saúda, se apresenta e se despede corretamente.", 'formFields' => [['name' => 'didGreet', 'label' => 'Bot iniciou com uma saudação?', 'type' => 'tri-state'], ['name' => 'identifiedUser', 'label' => 'Identificou o nome do utilizador?', 'type' => 'tri-state'], ['name' => 'offeredHelp', 'label' => 'Ofereceu ajuda ou apresentou-se?', 'type' => 'tri-state'], ['name' => 'didFarewell', 'label' => 'Despediu-se cordialmente no final?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações Adicionais', 'type' => 'textarea']]],
    ['id' => 'INTENT_RECOGNITION', 'name' => "Reconhecimento de Intenção", 'description' => "Avalia a capacidade do bot de compreender a intenção principal do utilizador.", 'formFields' => [['name' => 'userQuestion', 'label' => 'Pergunta/Frase do Utilizador', 'type' => 'textarea'], ['name' => 'expectedIntent', 'label' => 'Intenção Esperada', 'type' => 'text'], ['name' => 'botResponse', 'label' => 'Resposta do Bot', 'type' => 'textarea'], ['name' => 'result', 'label' => 'Resultado', 'type' => 'select', 'options' => ['Correto', 'Incorreto', 'Parcialmente Correto']]]],
    ['id' => 'CONTEXT_MANAGEMENT', 'name' => "Gestão de Contexto", 'description' => "Avalia a capacidade do bot de manter o contexto em múltiplos turnos de conversa.", 'formFields' => [['name' => 'initialQuery', 'label' => 'Pergunta Inicial', 'type' => 'textarea'], ['name' => 'followUpQuery', 'label' => 'Pergunta de Continuação (sem repetir o contexto)', 'type' => 'textarea'], ['name' => 'contextKept', 'label' => 'O bot manteve o contexto?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações de Contexto', 'type' => 'textarea']]],
    ['id' => 'PROMPT_INJECTION', 'name' => "Segurança: Injeção de Prompt", 'description' => "Tenta manipular o bot com instruções maliciosas para ignorar as suas diretrizes originais.", 'formFields' => [['name' => 'injectionAttempt', 'label' => 'Tentativa de Injeção de Prompt', 'type' => 'textarea'], ['name' => 'wasResisted', 'label' => 'O bot resistiu à injeção?', 'type' => 'tri-state'], ['name' => 'botFinalResponse', 'label' => 'Resposta Final do Bot', 'type' => 'textarea']]],
];

// =================================================================
// Bloco de Definição de Funções
// =================================================================

// --- FUNÇÕES DE BANCO DE DADOS ---
if (!function_exists('get_db_connection')) {
    function get_db_connection() {
        static $conn;
        if ($conn === null) {
            mysqli_report(MYSQLI_REPORT_OFF);
            $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
            if (!$conn) {
                $error_code = mysqli_connect_errno();
                $error_message = mysqli_connect_error();
                $connection_details = "Tentativa de conexão a " . DB_HOST . ":" . DB_PORT . " com o utilizador " . DB_USER . ".";
                error_log("DB Connection Error (Code: $error_code): $error_message. $connection_details");
                render_error_page(
                    "Erro de Conexão com o Banco de Dados (Código: $error_code)",
                    "Não foi possível conectar ao servidor de banco de dados.<br><br><b>Detalhes do Erro:</b> " . htmlspecialchars($error_message) . "<br><b>Detalhes da Tentativa:</b> " . htmlspecialchars($connection_details)
                );
                exit;
            }
            $conn->set_charset("utf8mb4");
        }
        return $conn;
    }
}

if (!function_exists('seed_initial_templates')) {
    function seed_initial_templates() {
        $conn = get_db_connection();
        $result = $conn->query("SELECT COUNT(*) as count FROM test_templates WHERE is_custom = 0");
        if ($result && $result->fetch_assoc()['count'] == 0) {
            $stmt = $conn->prepare("INSERT INTO test_templates (id, name, description, form_fields, is_custom) VALUES (?, ?, ?, ?, 0)");
            foreach (PRESET_TESTS as $template) {
                $formFieldsJson = json_encode($template['formFields']);
                $stmt->bind_param("ssss", $template['id'], $template['name'], $template['description'], $formFieldsJson);
                $stmt->execute();
            }
        }
    }
}

if (!function_exists('get_data')) {
    function get_data() {
        $conn = get_db_connection();
        $data = [
            'clients' => $conn->query("SELECT * FROM clients ORDER BY name ASC")->fetch_all(MYSQLI_ASSOC),
            'projects' => $conn->query("SELECT * FROM projects ORDER BY name ASC")->fetch_all(MYSQLI_ASSOC),
            'users' => $conn->query("SELECT id, name, email, role FROM users ORDER BY name ASC")->fetch_all(MYSQLI_ASSOC),
            'test_templates' => [], 'test_cases' => [], 'reports' => [],
        ];
        $templates_result = $conn->query("SELECT * FROM test_templates ORDER BY created_at DESC, name ASC");
        while ($row = $templates_result->fetch_assoc()) { $row['formFields'] = json_decode($row['form_fields'], true); $data['test_templates'][] = $row; }
        $test_cases_result = $conn->query("SELECT * FROM test_cases ORDER BY created_at DESC");
        while ($row = $test_cases_result->fetch_assoc()) { $row['custom_fields'] = json_decode($row['custom_fields'] ?? '[]', true); $row['paused_state'] = json_decode($row['paused_state'] ?? '[]', true); $data['test_cases'][] = $row; }
        $reports_result = $conn->query("SELECT * FROM reports ORDER BY execution_date DESC");
        while ($row = $reports_result->fetch_assoc()) { $row['results'] = json_decode($row['results'], true); $data['reports'][] = $row; }
        return $data;
    }
}

// --- FUNÇÕES DE AUTENTICAÇÃO E UTILITÁRIOS ---
if (!function_exists('login')) {
    function login($email, $password) {
        $conn = get_db_connection();
        $stmt = $conn->prepare("SELECT id, name, email, role, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password_hash'])) {
                unset($user['password_hash']);
                session_regenerate_id(true);
                $_SESSION['user'] = $user;
                return 'success';
            } else {
                return 'wrong_password';
            }
        } else {
            return 'user_not_found';
        }
    }
}

if (!function_exists('logout')) { function logout() { session_destroy(); header('Location: index.php?page=login'); exit; } }
if (!function_exists('is_logged_in')) { function is_logged_in() { return isset($_SESSION['user']) && is_array($_SESSION['user']); } }
if (!function_exists('get_current_user')) { function get_current_user() { return $_SESSION['user'] ?? null; } }
if (!function_exists('has_permission')) { function has_permission($roles) { $user = get_current_user(); return $user && in_array($user['role'], (array)$roles); } }

// --- LÓGICA DE NEGÓCIO (Ações do formulário) ---
if (!function_exists('handle_post_requests')) {
    function handle_post_requests() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        $conn = get_db_connection();
        $action = $_POST['action'] ?? '';
        $redirect_url = $_SERVER['REQUEST_URI'];

        try {
            switch ($action) {
                case 'login':
                    $loginResult = login($_POST['email'], $_POST['password']);
                    if ($loginResult === 'success') {
                        $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Login bem-sucedido!'];
                        // Adiciona o parâmetro de depuração para a próxima requisição
                        $redirect_url = 'index.php?page=dashboard&from_login=1';
                    } else {
                        $_SESSION['flash_message'] = ['type' => 'error', 'message' => $loginResult === 'wrong_password' ? 'A senha está incorreta.' : 'Nenhum utilizador encontrado com esse e-mail.'];
                        $redirect_url = 'index.php?page=login';
                    }
                    break;

                // Outros casos (add_client, add_project, etc.) continuam aqui...
                case 'add_client': if (has_permission('admin')) { $stmt = $conn->prepare("INSERT INTO clients (name) VALUES (?)"); $stmt->bind_param("s", $_POST['name']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Cliente adicionado!']; } break;
                case 'add_project': if (has_permission('admin')) { $p = $_POST['project']; $stmt = $conn->prepare("INSERT INTO projects (client_id, name, whatsapp_number, description, objective) VALUES (?, ?, ?, ?, ?)"); $stmt->bind_param("issss", $p['clientId'], $p['name'], $p['whatsappNumber'], $p['description'], $p['objective']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Projeto adicionado!']; } break;
                case 'add_user': if (has_permission('admin')) { $u = $_POST['user']; $hash = password_hash($u['password'], PASSWORD_DEFAULT); $stmt = $conn->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"); $stmt->bind_param("ssss", $u['name'], $u['email'], $hash, $u['role']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Utilizador adicionado!']; } break;
                // Adicione os outros 'cases' aqui...
            }
        } catch (mysqli_sql_exception $e) {
            error_log("SQL Error: " . $e->getMessage());
            $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Ocorreu um erro no banco de dados.'];
        }

        session_write_close();
        header('Location: ' . $redirect_url);
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

// --- FUNÇÕES DE RENDERIZAÇÃO ---
if (!function_exists('render_header')) {
    function render_header($title) {
    ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" /><title><?= htmlspecialchars($title) ?> - TestBot Manager</title><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; } details > summary { list-style: none; } details > summary::-webkit-details-marker { display: none; }</style></head><body class="bg-gray-100 text-gray-900"><?php
    }
}

if (!function_exists('render_footer')) { function render_footer() { ?></body></html><?php } }

if (!function_exists('render_flash_message')) {
    function render_flash_message() {
        if (isset($_SESSION['flash_message'])) {
            $flash = $_SESSION['flash_message'];
            $colors = ['success' => 'bg-green-100 border-green-500 text-green-700', 'error' => 'bg-red-100 border-red-500 text-red-700', 'info' => 'bg-blue-100 border-blue-500 text-blue-700'];
            echo '<div class="' . ($colors[$flash['type']] ?? $colors['info']) . ' border-l-4 p-4 mb-4 rounded-r-lg" role="alert"><p>' . htmlspecialchars($flash['message']) . '</p></div>';
            unset($_SESSION['flash_message']);
        }
    }
}

if (!function_exists('render_app_layout')) {
    function render_app_layout($page, callable $content_renderer, $all_data) {
        $user = get_current_user();
        $pageTitles = ['dashboard' => "Dashboard", 'test-management' => "Gerir Testes", 'user-management' => "Gerir Utilizadores", 'reports' => "Relatórios", 'client-management' => "Gerir Clientes", 'project-management' => "Gerir Projetos", 'test-guidelines' => "Orientações de Teste", 'custom-templates' => "Modelos Personalizados"];
        $title = $pageTitles[$page] ?? 'Detalhes';
        render_header($title);
        $navItems = [
            'admin' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()], ['name' => "Clientes", 'path' => "client-management", 'icon' => BuildingIcon()], ['name' => "Projetos", 'path' => "project-management", 'icon' => FolderIcon()], ['name' => "Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()], ['name' => "Utilizadores", 'path' => "user-management", 'icon' => UsersIcon()], ['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()], ['name' => "Modelos", 'path' => "custom-templates", 'icon' => BeakerIcon()]],
            'tester' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()], ['name' => "Meus Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()], ['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()]],
            'client' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()], ['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()]],
        ];
        $userNav = $navItems[$user['role']] ?? [];
        ?>
        <div class="flex h-screen bg-gray-100">
            <div class="hidden md:flex flex-col w-64 bg-white border-r">
                <div class="flex items-center justify-center h-16 border-b"><h1 class="text-2xl font-bold text-cyan-600">TestBot</h1></div>
                <div class="flex-1 overflow-y-auto p-4">
                    <nav class="space-y-2"><?php foreach ($userNav as $item): ?><a href="index.php?page=<?= $item['path'] ?>" class="flex items-center gap-3 px-4 py-2.5 rounded-lg <?= $page === $item['path'] ? 'bg-cyan-500 text-white' : 'text-gray-600 hover:bg-gray-100' ?>"><?= $item['icon']('w-5 h-5') ?><span><?= htmlspecialchars($item['name']) ?></span></a><?php endforeach; ?></nav>
                </div>
                <div class="p-4 border-t"><p class="font-semibold"><?= htmlspecialchars($user['name']) ?></p><p class="text-sm text-gray-500 capitalize"><?= htmlspecialchars($user['role']) ?></p><a href="index.php?page=logout" class="flex items-center gap-2 mt-2 text-sm text-gray-500 hover:text-red-500"><?= LogOutIcon('w-5 h-5') ?>Sair</a></div>
            </div>
            <div class="flex-1 flex flex-col overflow-hidden">
                <header class="bg-white border-b"><div class="px-6 py-4"><h1 class="text-xl font-semibold"><?= htmlspecialchars($title) ?></h1></div></header>
                <main class="flex-1 overflow-y-auto p-6"><?php render_flash_message(); $content_renderer($all_data); ?></main>
            </div>
        </div>
        <?php
        render_footer();
    }
}

if (!function_exists('render_login_page')) {
    function render_login_page() {
        render_header('Login');
        ?>
        <div class="min-h-screen flex items-center justify-center bg-gray-100">
            <div class="bg-white p-8 rounded-xl shadow-md w-full max-w-sm">
                <h1 class="text-3xl font-bold text-center mb-2">TestBot</h1>
                <p class="text-center text-gray-500 mb-8">Manager Login</p>
                <?php render_flash_message(); ?>
                <form method="POST" action="index.php">
                    <input type="hidden" name="action" value="login">
                    <div class="mb-4"><label class="block text-sm font-bold mb-2" for="email">Email</label><input id="email" name="email" type="email" required class="w-full p-3 bg-gray-50 border rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"></div>
                    <div class="mb-6"><label class="block text-sm font-bold mb-2" for="password">Senha</label><input id="password" name="password" type="password" required class="w-full p-3 bg-gray-50 border rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"></div>
                    <button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold hover:bg-cyan-600">Entrar</button>
                </form>
            </div>
        </div>
        <?php
        render_footer();
    }
}

// ... As outras funções de renderização (render_dashboard_page, etc.) não precisam de alteração.

if (!function_exists('render_dashboard_page')) {
    function render_dashboard_page($data) {
        $user = get_current_user();
        $firstName = explode(' ', $user['name'])[0];
        $stats = [];
        if($user['role'] === 'tester') {
            $assignedTests = count(array_filter($data['test_cases'], fn($tc) => $tc['assigned_to_id'] == $user['id']));
            $completedTests = count(array_filter($data['reports'], fn($r) => $r['tester_id'] == $user['id']));
            $pendingTests = count(array_filter($data['test_cases'], fn($tc) => $tc['assigned_to_id'] == $user['id'] && $tc['status'] === 'pending'));
            $stats = [['title' => "Testes Atribuídos", 'value' => $assignedTests], ['title' => "Testes Realizados", 'value' => $completedTests], ['title' => "Testes Pendentes", 'value' => $pendingTests]];
        } else {
            $stats = [['title' => "Relatórios Gerados", 'value' => count($data['reports'])], ['title' => "Projetos Ativos", 'value' => count($data['projects'])], ['title' => "Clientes na Base", 'value' => count($data['clients'])]];
        }
        ?>
        <div class="space-y-6">
            <h2 class="text-2xl font-bold">Olá, <?= htmlspecialchars($firstName) ?>!</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <?php foreach($stats as $stat): ?>
                <div class="bg-white p-6 rounded-lg shadow"><h3 class="text-gray-500"><?= htmlspecialchars($stat['title']) ?></h3><p class="text-3xl font-bold mt-2"><?= $stat['value'] ?></p></div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php
    }
}


if (!function_exists('render_error_page')) {
    function render_error_page($title, $message) {
        if (!headers_sent()) { render_header("Erro"); }
        ?>
        <div class="min-h-screen flex items-center justify-center">
            <div class="bg-white p-8 rounded-lg shadow-md max-w-lg text-center">
                <h1 class="text-2xl font-bold text-red-600 mb-4"><?= htmlspecialchars($title) ?></h1>
                <div class="text-left bg-red-50 border border-red-200 p-4 rounded"><?= $message ?></div>
            </div>
        </div>
        <?php
        if (!headers_sent()) { render_footer(); }
    }
}


// =================================================================
// Bloco de Execução Principal
// =================================================================

handle_post_requests();

$page = $_GET['page'] ?? (is_logged_in() ? 'dashboard' : 'login');

if ($page === 'logout') {
    logout();
}

if (!is_logged_in() && $page !== 'login') {
    header('Location: index.php?page=login');
    exit;
}

if (is_logged_in() && $page === 'login') {
    header('Location: index.php?page=dashboard');
    exit;
}

// Mapa de páginas e permissões
$pages = [
    'dashboard' => ['renderer' => 'render_dashboard_page', 'roles' => ['admin', 'tester', 'client']],
    'client-management' => ['renderer' => 'render_client_management_page', 'roles' => ['admin']],
    'project-management' => ['renderer' => 'render_project_management_page', 'roles' => ['admin']],
    'user-management' => ['renderer' => 'render_user_management_page', 'roles' => ['admin']],
    'test-management' => ['renderer' => 'render_test_management_page', 'roles' => ['admin', 'tester']],
    'reports' => ['renderer' => 'render_reports_page', 'roles' => ['admin', 'tester', 'client']],
];

// Carrega os dados apenas se o utilizador estiver logado
if(is_logged_in()) {
    seed_initial_templates();
    $all_data = get_data();
} else {
    $all_data = []; // Não precisa de dados para a página de login
}


// Renderiza a página
if ($page === 'login') {
    render_login_page();
} elseif (isset($pages[$page]) && has_permission($pages[$page]['roles'])) {
    // A função has_permission já verifica se o utilizador está logado
    render_app_layout($page, $pages[$page]['renderer'], $all_data);
} else {
    // Se a página não existe ou não tem permissão, redireciona para o login ou dashboard
    $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Acesso negado ou página não encontrada.'];
    header('Location: index.php?page=' . (is_logged_in() ? 'dashboard' : 'login'));
    exit;
}
?>
