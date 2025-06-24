<?php
// Inicia a sessão no topo de todas as páginas. Essencial para autenticação.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- CONFIGURAÇÃO DO BANCO DE DADOS E CONSTANTES ---
/*
 * ATENÇÃO: As credenciais do banco de dados foram atualizadas para usar o utilizador 'root'.
 * Verifique se estes valores correspondem exatamente à configuração do seu ambiente (EasyPanel/Docker).
 */
define('DB_HOST', 'lab_mysql'); // Hostname do serviço do banco de dados (geralmente o nome do contentor)
define('DB_USER', 'root');       // Utilizador do banco de dados (alterado para 'root')
define('DB_PASS', 'd21d846891a08dfaa82b'); // Senha do utilizador root
define('DB_NAME', 'testbot');     // Nome do banco de dados
define('DB_PORT', 3306);          // Porta do banco de dados

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
                $user_error_message = "Não foi possível conectar ao servidor de banco de dados.<br><br><b>Detalhes do Erro:</b> " . htmlspecialchars($error_message) . "<br><b>Detalhes da Tentativa:</b> " . htmlspecialchars($connection_details) . "<br><br>Por favor, verifique se as constantes DB_HOST, DB_USER, DB_PASS, DB_NAME e DB_PORT no topo do ficheiro estão corretas e se o serviço do banco de dados está acessível a partir da aplicação.";
                render_error_page(
                    "Erro de Conexão com o Banco de Dados (Código: $error_code)",
                    $user_error_message
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
if (!function_exists('login')) { function login($email, $password) { $conn = get_db_connection(); $stmt = $conn->prepare("SELECT id, name, email, role, password_hash FROM users WHERE email = ?"); $stmt->bind_param("s", $email); $stmt->execute(); $result = $stmt->get_result(); if ($user = $result->fetch_assoc()) { if (password_verify($password, $user['password_hash'])) { unset($user['password_hash']); $_SESSION['user'] = $user; return true; } } return false; } }
if (!function_exists('logout')) { function logout() { session_destroy(); header('Location: index.php?page=login'); exit; } }
if (!function_exists('is_logged_in')) { function is_logged_in() { return isset($_SESSION['user']) && is_array($_SESSION['user']); } }

// Garante que a função sempre retorne um array ou null.
if (!function_exists('get_current_user')) { 
    function get_current_user() { 
        if (isset($_SESSION['user']) && is_array($_SESSION['user'])) {
            return $_SESSION['user'];
        }
        return null;
    } 
}

// Torna a verificação de permissão mais segura.
if (!function_exists('has_permission')) { 
    function has_permission($roles) { 
        $user = get_current_user(); 
        if (!is_array($user) || !isset($user['role'])) {
            return false;
        }
        return in_array($user['role'], (array)$roles); 
    } 
}

// --- LÓGICA DE NEGÓCIO (Ações do formulário) ---
if (!function_exists('handle_post_requests')) {
    function handle_post_requests() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        $conn = get_db_connection();
        $action = $_POST['action'] ?? '';
        $user = get_current_user();
        try {
            switch ($action) {
                case 'login': if (login($_POST['email'], $_POST['password'])) { $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Login bem-sucedido!']; header('Location: index.php?page=dashboard'); exit; } $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Credenciais inválidas.']; header('Location: index.php?page=login'); exit;
                case 'add_client': if (has_permission('admin')) { $stmt = $conn->prepare("INSERT INTO clients (name) VALUES (?)"); $stmt->bind_param("s", $_POST['name']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Cliente adicionado com sucesso!']; } break;
                case 'add_project': if (has_permission('admin')) { $p = $_POST['project']; $stmt = $conn->prepare("INSERT INTO projects (client_id, name, whatsapp_number, description, objective) VALUES (?, ?, ?, ?, ?)"); $stmt->bind_param("issss", $p['clientId'], $p['name'], $p['whatsappNumber'], $p['description'], $p['objective']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Projeto adicionado com sucesso!']; } break;
                case 'add_user': if (has_permission('admin')) { $u = $_POST['user']; $password_hash = password_hash($u['password'], PASSWORD_DEFAULT); $stmt = $conn->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"); $stmt->bind_param("ssss", $u['name'], $u['email'], $password_hash, $u['role']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Utilizador adicionado com sucesso!']; } break;
                case 'add_test': if (has_permission('admin')) { $t = $_POST['test']; $test_id = 'TEST-' . time(); $custom_fields_json = $_POST['customFields'] ?? '[]'; $stmt = $conn->prepare("INSERT INTO test_cases (id, project_id, template_id, assigned_to_id, custom_fields) VALUES (?, ?, ?, ?, ?)"); $stmt->bind_param("sisis", $test_id, $t['projectId'], $t['typeId'], $t['assignedTo'], $custom_fields_json); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Caso de teste criado com sucesso!']; } break;
                case 'execute_test':
                    if (has_permission('tester') && $user) {
                        $testCaseId = $_POST['test_case_id']; $resultsJson = json_encode($_POST['results']); $reportId = 'REP-' . time(); $executionDate = date('Y-m-d H:i:s');
                        $conn->begin_transaction();
                        $stmt_update = $conn->prepare("UPDATE test_cases SET status = 'completed', paused_state = NULL WHERE id = ?"); $stmt_update->bind_param("s", $testCaseId); $stmt_update->execute();
                        $stmt_insert = $conn->prepare("INSERT INTO reports (id, test_case_id, tester_id, execution_date, results) VALUES (?, ?, ?, ?, ?)"); $stmt_insert->bind_param("ssiss", $reportId, $testCaseId, $user['id'], $executionDate, $resultsJson); $stmt_insert->execute();
                        $conn->commit();
                        $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Teste concluído e relatório gerado!'];
                    }
                    break;
                case 'pause_test': if (has_permission('tester')) { $pausedStateJson = json_encode($_POST['results']); $stmt = $conn->prepare("UPDATE test_cases SET status = 'paused', paused_state = ? WHERE id = ?"); $stmt->bind_param("ss", $pausedStateJson, $_POST['test_case_id']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Teste pausado com sucesso.']; } break;
                case 'resume_test': if (has_permission('tester')) { $stmt = $conn->prepare("UPDATE test_cases SET status = 'pending' WHERE id = ?"); $stmt->bind_param("s", $_POST['test_case_id']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'info', 'message' => 'Teste retomado.']; } break;
                case 'add_custom_template': if (has_permission('admin')) { $t = $_POST['template']; $template_id = 'CUSTOM-' . time(); $form_fields_json = $_POST['formFields'] ?? '[]'; $stmt = $conn->prepare("INSERT INTO test_templates (id, name, description, form_fields, is_custom) VALUES (?, ?, ?, ?, 1)"); $stmt->bind_param("ssss", $template_id, $t['name'], $t['description'], $form_fields_json); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Modelo personalizado criado com sucesso!']; } break;
            }
        } catch (mysqli_sql_exception $e) {
            error_log("SQL Error: " . $e->getMessage());
            if ($conn->in_transaction) { $conn->rollback(); }
            $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Ocorreu um erro ao processar a sua solicitação.'];
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

// --- FUNÇÕES DE RENDERIZAÇÃO ---
if (!function_exists('render_header')) {
    function render_header($title) {
    ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" /><title><?= htmlspecialchars($title) ?> - TestBot Manager</title><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; overscroll-behavior-y: contain; } .content-scrollable::-webkit-scrollbar { display: none; } .content-scrollable { -ms-overflow-style: none; scrollbar-width: none; } details > summary { list-style: none; } details > summary::-webkit-details-marker { display: none; }</style></head><body class="bg-gray-100 text-gray-900 min-h-screen antialiased"><?php
    }
}

if (!function_exists('render_footer')) {
    function render_footer() {
    ?></body></html><?php
    }
}

if (!function_exists('render_flash_message')) {
    function render_flash_message() {
        if (isset($_SESSION['flash_message'])) {
            $flash = $_SESSION['flash_message'];
            $colors = [
                'success' => 'bg-green-100 border-green-500 text-green-700',
                'error' => 'bg-red-100 border-red-500 text-red-700',
                'info' => 'bg-blue-100 border-blue-500 text-blue-700'
            ];
            $colorClass = $colors[$flash['type']] ?? $colors['info'];
            echo '<div class="' . $colorClass . ' border-l-4 p-4 mb-4 rounded-r-lg" role="alert"><p>' . htmlspecialchars($flash['message']) . '</p></div>';
            unset($_SESSION['flash_message']);
        }
    }
}

// CORREÇÃO: Adicionada lógica de autocorreção de sessão.
if (!function_exists('render_app_layout')) {
    function render_app_layout($page, callable $content_renderer, $all_data) {
        $user = get_current_user();

        // MECANISMO DE AUTOCORREÇÃO: Se a sessão do utilizador estiver corrompida (não for um array),
        // força o logout para limpar a sessão e redireciona para a página de login.
        if (!is_array($user) || !isset($user['role']) || !isset($user['name'])) {
            logout();
        }
        
        $pageTitles = ['dashboard' => "Dashboard", 'test-management' => "Gerir Testes", 'user-management' => "Gerir Utilizadores", 'reports' => "Relatórios", 'client-management' => "Gerir Clientes", 'project-management' => "Gerir Projetos", 'test-guidelines' => "Orientações de Teste", 'custom-templates' => "Modelos Personalizados"];
        $title = $pageTitles[$page] ?? 'Detalhes';
        render_header($title);
        $navItems = [
            'admin' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Clientes", 'path' => "client-management", 'icon' => BuildingIcon()],['name' => "Projetos", 'path' => "project-management", 'icon' => FolderIcon()],['name' => "Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Utilizadores", 'path' => "user-management", 'icon' => UsersIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Modelos", 'path' => "custom-templates", 'icon' => BeakerIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]],
            'tester' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Meus Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]],
            'client' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]],
        ];
        
        $userNav = $navItems[$user['role']];
        ?>
        <div class="h-screen w-screen flex flex-col sm:flex-row bg-gray-100">
            <div class="hidden sm:flex flex-col w-64 bg-white border-r border-gray-200 p-4">
                <h1 class="text-2xl font-bold text-cyan-600 mb-10 px-2">TestBot</h1>
                <nav class="flex-1 space-y-2"><?php foreach ($userNav as $item): $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="w-full flex items-center gap-3 text-left py-2.5 px-4 rounded-lg transition-colors text-base font-semibold <?= $isActive ? 'bg-cyan-500 text-white shadow-sm' : 'text-gray-600 hover:bg-gray-100' ?>"><?= $item['icon']('class="w-5 h-5"') ?><?= htmlspecialchars($item['name']) ?></a><?php endforeach; ?></nav>
                <div class="pt-6 border-t border-gray-200"><p class="text-sm font-semibold text-gray-800"><?= htmlspecialchars($user['name']) ?></p><p class="text-xs text-gray-500 capitalize"><?= htmlspecialchars($user['role']) ?></p></div>
            </div>
            <div class="flex-1 flex flex-col overflow-hidden">
                <header class="bg-white/80 backdrop-blur-lg border-b border-gray-200 w-full z-10"><div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8"><div class="flex items-center justify-between h-16"><h1 class="text-lg font-bold text-gray-800"><?= htmlspecialchars($title) ?></h1><a href="index.php?page=logout" class="hidden sm:flex items-center gap-2 text-sm font-semibold text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-5 h-5"') ?>Sair</a></div></div></header>
                <main class="flex-1 overflow-y-auto content-scrollable p-4 sm:p-6 pb-24 sm:pb-6"><?php render_flash_message(); $content_renderer($all_data); ?></main>
                <nav class="sm:hidden fixed bottom-0 left-0 right-0 bg-white/80 backdrop-blur-lg border-t border-gray-200 z-20"><div class="flex justify-around items-center h-16"><?php foreach ($userNav as $item): if(count($userNav) > 4 && $item['name'] === 'Orientações') continue; $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="flex flex-col items-center justify-center w-full h-full transition-colors <?= $isActive ? 'text-cyan-500' : 'text-gray-500 hover:text-cyan-500' ?>"><?= $item['icon']('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium"><?= htmlspecialchars($item['name']) ?></span></a><?php endforeach; ?><a href="index.php?page=logout" class="flex flex-col items-center justify-center w-full h-full text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium">Sair</span></a></div></nav>
            </div>
        </div>
        <?php render_footer();
    }
}

if (!function_exists('render_login_page')) {
    function render_login_page($data) {
        render_header('Login');
        ?><div class="min-h-screen flex items-center justify-center bg-gray-100 px-4"><div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm"><h1 class="text-3xl font-bold text-gray-800 text-center mb-2">TestBot</h1><p class="text-center text-gray-500 mb-8">Manager Login</p><?php render_flash_message(); ?><form method="POST" action="index.php"><input type="hidden" name="action" value="login"><div class="mb-4"><label class="text-sm font-bold text-gray-600 mb-1 block" for="email">Email</label><input id="email" name="email" type="email" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><div class="mb-6"><label class="text-sm font-bold text-gray-600 mb-1 block" for="password">Senha</label><input id="password" name="password" type="password" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg hover:bg-cyan-600 transition duration-200 font-bold">Entrar</button></form></div></div><?php
        render_footer();
    }
}

if (!function_exists('render_dashboard_page')) {
    function render_dashboard_page($data) {
        $user = get_current_user();
        if ($user['role'] === 'tester') {
            $assignedTests = array_filter($data['test_cases'], fn($tc) => $tc['assigned_to_id'] == $user['id']);
            $completedTests = array_filter($data['reports'], fn($r) => $r['tester_id'] == $user['id']);
            $stats = [['title' => "Testes Atribuídos", 'value' => count($assignedTests), 'color' => 'indigo'], ['title' => "Testes Realizados", 'value' => count($completedTests), 'color' => 'green'], ['title' => "Testes Pendentes", 'value' => count(array_filter($assignedTests, fn($tc) => $tc['status'] === 'pending')), 'color' => 'blue']];
        } else {
             $stats = [['title' => "Relatórios Gerados", 'value' => count($data['reports']), 'color' => 'cyan'], ['title' => "Projetos Ativos", 'value' => count($data['projects']), 'color' => 'blue'], ['title' => "Clientes na Base", 'value' => count($data['clients']), 'color' => 'indigo']];
        }
        $firstName = explode(' ', $user['name'])[0];
        ?>
        <div class="space-y-6"><h2 class="text-2xl font-bold text-gray-800">Olá, <?= htmlspecialchars($firstName) ?>!</h2><div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
        <?php foreach($stats as $stat): $colors = ['blue'=>'from-blue-500 to-blue-400', 'cyan'=>'from-cyan-500 to-cyan-400', 'indigo'=>'from-indigo-500 to-indigo-400', 'green'=>'from-green-500 to-green-400']; ?>
        <div class="bg-white p-5 rounded-xl shadow-sm"><h3 class="text-sm font-semibold text-gray-600"><?= htmlspecialchars($stat['title']) ?></h3><p class="text-3xl font-bold mt-2 bg-clip-text text-transparent bg-gradient-to-r <?= $colors[$stat['color']] ?>"><?= $stat['value'] ?></p></div>
        <?php endforeach; ?></div></div><?php
    }
}

if (!function_exists('render_management_page')) {
    function render_management_page($title, $item_name, $items, callable $render_item, callable $render_form) {
        ?>
        <div class="space-y-6">
            <details class="bg-white rounded-xl shadow-sm"><summary class="p-4 sm:p-6 cursor-pointer font-bold text-lg flex justify-between items-center"><span>Adicionar Novo <?= htmlspecialchars($item_name) ?></span><?= PlusIcon('w-5 h-5') ?></summary><div class="p-4 sm:p-6 border-t"><?php $render_form(); ?></div></details>
            <div class="bg-white rounded-xl shadow-sm p-4 sm:p-6"><h3 class="font-bold text-lg mb-4"><?= htmlspecialchars($title) ?></h3><div class="space-y-3">
            <?php if (empty($items)): ?><p class="text-gray-500">Nenhum item encontrado.</p>
            <?php else: foreach ($items as $item): $render_item($item); endforeach; endif; ?>
            </div></div>
        </div>
        <?php
    }
}

if (!function_exists('render_client_management_page')) {
    function render_client_management_page($data) {
        render_management_page('Clientes', 'Cliente', $data['clients'],
            function($c) { echo '<div class="bg-gray-50 p-3 rounded-lg font-semibold">' . htmlspecialchars($c['name']) . '</div>'; },
            function() { ?> <form method="POST"><input type="hidden" name="action" value="add_client"><input type="text" name="name" placeholder="Nome do Cliente" required class="w-full p-3 bg-gray-50 border rounded-lg mb-4"><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold">Salvar Cliente</button></form> <?php }
        );
    }
}

if (!function_exists('render_project_management_page')) {
    function render_project_management_page($data) {
        render_management_page('Projetos', 'Projeto', $data['projects'],
            function($p) use ($data) {
                $client = current(array_filter($data['clients'], fn($c) => $c['id'] == $p['client_id'])) ?: ['name' => 'N/A'];
                echo '<div class="bg-gray-50 p-4 rounded-lg"><p class="font-bold">'.htmlspecialchars($p['name']).'</p><p class="text-sm text-cyan-600 font-semibold">'.htmlspecialchars($p['whatsapp_number']).'</p><p class="text-sm text-gray-500 mt-1">'.htmlspecialchars($client['name']).'</p><p class="text-sm text-gray-700 mt-2">'.htmlspecialchars($p['description']).'</p></div>';
            },
            function() use ($data) { ?>
                <form method="POST" class="space-y-4"><input type="hidden" name="action" value="add_project"><input type="text" name="project[name]" placeholder="Nome do Projeto" required class="w-full p-3 bg-gray-50 border rounded-lg"><input type="text" name="project[whatsappNumber]" placeholder="Nº de WhatsApp" required class="w-full p-3 bg-gray-50 border rounded-lg"><textarea name="project[description]" placeholder="Descrição" class="w-full p-3 bg-gray-50 border rounded-lg min-h-[80px]"></textarea><textarea name="project[objective]" placeholder="Objetivo" class="w-full p-3 bg-gray-50 border rounded-lg min-h-[80px]"></textarea><select name="project[clientId]" required class="w-full p-3 bg-gray-50 border rounded-lg"><option value="">Selecione um Cliente</option>
                <?php foreach($data['clients'] as $c) echo '<option value="'.htmlspecialchars($c['id']).'">'.htmlspecialchars($c['name']).'</option>'; ?>
                </select><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold">Salvar Projeto</button></form>
            <?php }
        );
    }
}

if (!function_exists('render_user_management_page')) {
    function render_user_management_page($data) {
        render_management_page('Utilizadores', 'Utilizador', $data['users'],
            function($u) { echo '<div class="bg-gray-50 rounded-lg p-4 flex justify-between items-center"><div><p class="font-semibold">'.htmlspecialchars($u['name']).'</p><p class="text-sm text-gray-500">'.htmlspecialchars($u['email']).'</p></div><span class="px-2 py-1 text-xs font-semibold rounded-full bg-indigo-100 text-indigo-800 capitalize">'.htmlspecialchars($u['role']).'</span></div>'; },
            function() { ?>
                <form method="POST" class="space-y-4"><input type="hidden" name="action" value="add_user"><input type="text" name="user[name]" placeholder="Nome Completo" required class="w-full p-3 bg-gray-50 border rounded-lg"><input type="email" name="user[email]" placeholder="Email" required class="w-full p-3 bg-gray-50 border rounded-lg"><input type="password" name="user[password]" placeholder="Senha" required class="w-full p-3 bg-gray-50 border rounded-lg"><select name="user[role]" required class="w-full p-3 bg-gray-50 border rounded-lg"><option value="tester">Tester</option><option value="client">Cliente</option><option value="admin">Admin</option></select><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold">Salvar Utilizador</button></form>
            <?php }
        );
    }
}

if (!function_exists('render_test_management_page')) {
    function render_test_management_page($data) {
        $user = get_current_user();
        $filteredTestCases = array_filter($data['test_cases'], fn($tc) => has_permission('admin') || $tc['assigned_to_id'] == $user['id']);
        $statusStyles = ['pending' => "bg-yellow-100 text-yellow-800", 'completed' => "bg-green-100 text-green-800", 'paused' => "bg-orange-100 text-orange-800"];
        ?>
        <div class="space-y-6">
            <?php if (has_permission('admin')): ?>
            <details class="bg-white rounded-xl shadow-sm"><summary class="p-4 sm:p-6 cursor-pointer font-bold text-lg flex justify-between items-center"><span>Criar Novo Teste</span><?= PlusIcon('w-5 h-5') ?></summary>
                <div class="p-4 sm:p-6 border-t">
                    <form method="POST" id="form-create-test" class="space-y-4">
                        <input type="hidden" name="action" value="add_test">
                        <select id="client-select" class="w-full p-3 bg-gray-50 border rounded-lg"><option value="">1. Selecione um Cliente</option>
                            <?php foreach($data['clients'] as $c) echo '<option value="'.htmlspecialchars($c['id']).'">'.htmlspecialchars($c['name']).'</option>'; ?>
                        </select>
                        <select name="test[projectId]" id="project-select" required class="w-full p-3 bg-gray-50 border rounded-lg disabled:bg-gray-200" disabled><option value="">2. Selecione um Projeto</option></select>
                        <select name="test[typeId]" required class="w-full p-3 bg-gray-50 border rounded-lg"><option value="">3. Selecione o Tipo de Teste</option>
                            <optgroup label="Modelos Predefinidos"><?php foreach(array_filter($data['test_templates'], fn($t) => !$t['is_custom']) as $pt) echo '<option value="'.htmlspecialchars($pt['id']).'">'.htmlspecialchars($pt['name']).'</option>'; ?></optgroup>
                            <?php if(!empty(array_filter($data['test_templates'], fn($t) => $t['is_custom']))): ?><optgroup label="Modelos Personalizados"><?php foreach(array_filter($data['test_templates'], fn($t) => $t['is_custom']) as $ct) echo '<option value="'.htmlspecialchars($ct['id']).'">'.htmlspecialchars($ct['name']).'</option>'; ?></optgroup><?php endif; ?>
                        </select>
                        <select name="test[assignedTo]" required class="w-full p-3 bg-gray-50 border rounded-lg"><option value="">4. Atribuir a um Testador</option>
                            <?php foreach(array_filter($data['users'], fn($u) => $u['role'] === 'tester') as $u) echo '<option value="'.htmlspecialchars($u['id']).'">'.htmlspecialchars($u['name']).'</option>'; ?>
                        </select>
                        <input type="hidden" name="customFields" id="custom-fields-json">
                        <button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold">Adicionar Teste</button>
                    </form>
                    <script>
                        const projectsByClient = <?= json_encode(array_reduce($data['projects'], function($acc, $p) { $acc[$p['client_id']][] = $p; return $acc; }, [])) ?>;
                        document.getElementById('client-select').addEventListener('change', function() {
                            const projectSelect = document.getElementById('project-select');
                            projectSelect.innerHTML = '<option value="">2. Selecione um Projeto</option>';
                            const projects = projectsByClient[this.value] || [];
                            projects.forEach(p => projectSelect.innerHTML += `<option value="${p.id}">${p.name}</option>`);
                            projectSelect.disabled = projects.length === 0;
                        });
                    </script>
                </div>
            </details>
            <?php endif; ?>
            <div class="space-y-4">
            <?php if (empty($filteredTestCases)): ?><div class="text-center py-10 bg-white rounded-xl shadow-sm"><p class="text-gray-500">Nenhum teste encontrado.</p></div>
            <?php else: foreach ($filteredTestCases as $tc): 
                $preset = current(array_filter($data['test_templates'], fn($p) => $p['id'] === $tc['template_id'])) ?: [];
                $project = current(array_filter($data['projects'], fn($p) => $p['id'] === $tc['project_id'])) ?: [];
                $client = current(array_filter($data['clients'], fn($c) => $c['id'] == ($project['client_id'] ?? null))) ?: [];
            ?>
                <div class="bg-white rounded-xl shadow-sm overflow-hidden" id="test-<?= htmlspecialchars($tc['id']) ?>"><div class="p-4"><div class="flex justify-between items-start"><div><p class="text-xs font-semibold text-cyan-600"><?= htmlspecialchars($client['name'] ?? 'N/A') ?></p><h3 class="font-bold text-gray-800"><?= htmlspecialchars($preset['name'] ?? 'N/A') ?></h3><p class="text-sm text-gray-500"><?= htmlspecialchars($project['name'] ?? 'N/A') ?> - <?= htmlspecialchars($project['whatsapp_number'] ?? 'N/A') ?></p></div><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full <?= $statusStyles[$tc['status']] ?>"><?= htmlspecialchars($tc['status']) ?></span></div><p class="text-sm text-gray-600 mt-2"><?= htmlspecialchars($preset['description'] ?? 'N/A') ?></p>
                    <?php if (has_permission('tester') && $tc['status'] !== 'completed'): ?>
                    <div class="pt-4 mt-4 border-t border-gray-200">
                        <?php if ($tc['status'] === 'pending'): ?><button onclick="document.getElementById('exec-form-<?= htmlspecialchars($tc['id']) ?>').style.display='block'; this.style.display='none';" class="w-full bg-blue-500 text-white p-2 rounded-lg hover:bg-blue-600 transition font-semibold text-sm">Iniciar Execução</button>
                        <?php elseif ($tc['status'] === 'paused'): ?><form method="POST" style="display:inline-block; width: 100%;"><input type="hidden" name="action" value="resume_test"><input type="hidden" name="test_case_id" value="<?= htmlspecialchars($tc['id']) ?>"><button type="submit" class="w-full bg-orange-500 text-white p-2 rounded-lg hover:bg-orange-600 transition font-semibold text-sm">Retomar Execução</button></form>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>
                </div>
                <div id="exec-form-<?= htmlspecialchars($tc['id']) ?>" class="bg-gray-50 border-t border-gray-200 p-4 space-y-4" style="display:none;"><h4 class="font-bold text-gray-700">Executando: <?= htmlspecialchars($preset['name'] ?? '') ?></h4><form method="POST"><input type="hidden" name="test_case_id" value="<?= htmlspecialchars($tc['id']) ?>">
                <?php $allFields = array_merge($preset['formFields'] ?? [], $tc['custom_fields'] ?? []); $pausedState = $tc['paused_state'] ?? [];
                foreach ($allFields as $field): ?>
                <div><label class="block text-sm font-semibold text-gray-600 mb-1"><?= htmlspecialchars($field['label']) ?></label>
                <?php if ($field['type'] === 'textarea'): ?><textarea name="results[<?= htmlspecialchars($field['name']) ?>]" class="w-full p-2 bg-white border rounded-lg text-sm"><?= htmlspecialchars($pausedState[$field['name']] ?? '') ?></textarea>
                <?php elseif ($field['type'] === 'text'): ?><input type="text" name="results[<?= htmlspecialchars($field['name']) ?>]" value="<?= htmlspecialchars($pausedState[$field['name']] ?? '') ?>" class="w-full p-2 bg-white border rounded-lg text-sm">
                <?php elseif ($field['type'] === 'select'): ?><select name="results[<?= htmlspecialchars($field['name']) ?>]" class="w-full p-2 bg-white border rounded-lg text-sm"><option value="">Selecione...</option>
                    <?php foreach($field['options'] as $opt) echo '<option value="'.htmlspecialchars($opt).'" '.((($pausedState[$field['name']] ?? '') === $opt) ? 'selected' : '').'>'.htmlspecialchars($opt).'</option>'; ?>
                </select>
                <?php elseif ($field['type'] === 'tri-state'): ?><select name="results[<?= htmlspecialchars($field['name']) ?>]" class="w-full p-2 bg-white border rounded-lg text-sm"><option value="">Selecione...</option><option value="Sim" <?= (($pausedState[$field['name']] ?? '') === 'Sim') ? 'selected' : '' ?>>Sim</option><option value="Não" <?= (($pausedState[$field['name']] ?? '') === 'Não') ? 'selected' : '' ?>>Não</option><option value="N/A" <?= (($pausedState[$field['name']] ?? '') === 'N/A') ? 'selected' : '' ?>>Não se aplica</option></select>
                <?php endif; ?></div>
                <?php endforeach; ?>
                <div class="flex gap-2 pt-4"><button type="button" onclick="document.getElementById('exec-form-<?= htmlspecialchars($tc['id']) ?>').style.display='none'; document.querySelector('#test-<?= htmlspecialchars($tc['id']) ?> button').style.display='block';" class="w-full bg-gray-200 text-gray-700 p-2 rounded-lg font-semibold text-sm">Cancelar</button><button type="submit" name="action" value="pause_test" class="w-full bg-yellow-500 text-white p-2 rounded-lg font-semibold text-sm">Pausar</button><button type="submit" name="action" value="execute_test" class="w-full bg-green-500 text-white p-2 rounded-lg font-semibold text-sm">Concluir</button></div></form></div></div>
            <?php endforeach; endif; ?>
            </div>
        </div>
        <?php
    }
}

if (!function_exists('render_reports_page')) {
    function render_reports_page($data) {
        ?>
        <div class="space-y-6"><h2 class="text-xl font-bold text-gray-800">Relatórios de Execução</h2>
        <?php if (empty($data['reports'])): ?><div class="text-center py-10 bg-white rounded-xl shadow-sm"><p class="text-gray-500">Nenhum relatório gerado.</p></div>
        <?php else: ?>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <?php foreach ($data['reports'] as $report): 
            $testCase = current(array_filter($data['test_cases'], fn($tc) => $tc['id'] === $report['test_case_id'])) ?: [];
            $preset = current(array_filter($data['test_templates'], fn($p) => $p['id'] === ($testCase['template_id'] ?? null))) ?: [];
            $tester = current(array_filter($data['users'], fn($u) => $u['id'] === $report['tester_id'])) ?: [];
            $project = current(array_filter($data['projects'], fn($p) => $p['id'] === ($testCase['project_id'] ?? null))) ?: [];
            $client = current(array_filter($data['clients'], fn($c) => $c['id'] == ($project['client_id'] ?? null))) ?: [];
            $formattedDate = date('d/m/Y', strtotime($report['execution_date']));
        ?>
        <div class="bg-white rounded-xl shadow-sm p-4 space-y-3"><div><h3 class="font-bold text-gray-800"><?= htmlspecialchars($preset['name'] ?? 'N/A') ?></h3><p class="text-sm text-gray-500"><?= htmlspecialchars($project['name'] ?? 'N/A') ?></p></div><div class="text-xs text-gray-600 space-y-1"><p><span class="font-semibold">Testador:</span> <?= htmlspecialchars($tester['name'] ?? 'N/A') ?></p><p><span class="font-semibold">Data:</span> <?= htmlspecialchars($formattedDate) ?></p></div><div class="pt-3 border-t"><button onclick='openReportModal(<?= json_encode($report, JSON_HEX_APOS) ?>, <?= json_encode($testCase, JSON_HEX_APOS) ?>, <?= json_encode($preset, JSON_HEX_APOS) ?>, <?= json_encode($client, JSON_HEX_APOS) ?>, <?= json_encode($project, JSON_HEX_APOS) ?>, <?= json_encode($tester, JSON_HEX_APOS) ?>)' class="w-full bg-gray-100 text-gray-700 p-2 rounded-lg font-semibold text-sm">Ver Detalhes</button></div></div>
        <?php endforeach; ?>
        </div>
        <?php endif; ?>
        </div>
        <div id="report-modal" class="fixed inset-0 bg-black bg-opacity-60 z-50 flex items-center justify-center p-4" style="display: none;" onclick="this.style.display='none'"><div class="bg-white rounded-2xl shadow-xl w-full max-w-2xl" onclick="event.stopPropagation()"><div class="p-6 border-b"><h3 id="modal-title" class="text-lg font-bold"></h3></div><div id="modal-content" class="p-6 max-h-[70vh] overflow-y-auto"></div><div class="p-6 border-t"><button id="pdf-export-btn" class="w-full bg-blue-500 text-white p-2 rounded-lg font-semibold">Exportar para PDF</button></div></div></div>
        <script>
            function openReportModal(report, testCase, preset, client, project, tester) {
                const formattedDate = new Date(report.execution_date).toLocaleString('pt-BR', { dateStyle: 'long', timeStyle: 'short' });
                document.getElementById('modal-title').innerText = `Detalhes do Relatório ${report.id}`;
                let contentHtml = `<div class="space-y-4 text-sm"><div class="bg-gray-50 p-3 rounded-lg space-y-1"><p><span class="font-semibold">Teste:</span> ${preset.name || ''}</p><p><span class="font-semibold">Projeto:</span> ${project.name || ''}</p><p><span class="font-semibold">Cliente:</span> ${client.name || ''}</p><p><span class="font-semibold">Testador:</span> ${tester.name || ''}</p><p><span class="font-semibold">Data:</span> ${formattedDate}</p></div><h4 class="font-bold text-gray-800 pt-2 border-t">Resultados</h4><div class="space-y-2">`;
                const allFields = [...(preset.formFields || []), ...(testCase.custom_fields || [])];
                allFields.forEach(field => {
                    const resultValue = report.results[field.name] || 'Não preenchido';
                    contentHtml += `<div class="bg-gray-50 p-2 rounded-md"><p class="font-semibold text-gray-600">${field.label}</p><p class="text-gray-800 break-words">${resultValue}</p></div>`;
                });
                contentHtml += `</div></div>`;
                document.getElementById('modal-content').innerHTML = contentHtml;
                document.getElementById('pdf-export-btn').onclick = () => generatePDF(report, preset, client, project, tester, formattedDate, allFields);
                document.getElementById('report-modal').style.display = 'flex';
            }
            function generatePDF(report, preset, client, project, tester, formattedDate, allFields) {
                const { jsPDF } = window.jspdf;
                const doc = new jsPDF();
                doc.setFontSize(18); doc.text(`Relatório de Teste: ${preset.name}`, 14, 22);
                doc.setFontSize(11); doc.setTextColor(100); doc.text(`ID: ${report.id}`, 14, 32);
                doc.autoTable({ startY: 40, head: [['Detalhe', 'Informação']], body: [ ['Cliente', client.name], ['Projeto', project.name], ['Testador', tester.name], ['Data', formattedDate] ] });
                const finalY = doc.lastAutoTable.finalY || 10;
                doc.setFontSize(14); doc.text('Resultados da Execução', 14, finalY + 15);
                const tableBody = allFields.map(field => [field.label, report.results[field.name] || 'Não preenchido']);
                doc.autoTable({ startY: finalY + 20, head: [['Critério', 'Resultado']], body: tableBody, theme: 'grid' });
                doc.save(`relatorio-${report.test_case_id}.pdf`);
            }
        </script>
        <?php
    }
}

if (!function_exists('render_test_guidelines_page')) {
    function render_test_guidelines_page($data) {
        ?>
        <div class="space-y-6"><h2 class="text-2xl font-bold text-gray-800">Orientações de Teste</h2><p class="text-gray-600">Use este guia como referência para os testes predefinidos.</p>
        <div class="space-y-8">
        <?php foreach (array_filter($data['test_templates'], fn($t) => !$t['is_custom']) as $preset): ?>
        <div class="bg-white p-6 rounded-xl shadow-sm"><h3 class="text-lg font-bold text-cyan-600 mb-2"><?= htmlspecialchars($preset['name']) ?></h3><p class="text-sm text-gray-600 mb-4"><?= htmlspecialchars($preset['description']) ?></p><div class="border-t pt-4"><h4 class="font-semibold mb-2">Itens a Avaliar:</h4><ul class="list-disc list-inside space-y-2 text-sm">
        <?php foreach ($preset['formFields'] as $field): 
            $guideline = match($field['type']) { 'tri-state' => 'Marque "Sim", "Não" ou "Não se Aplica".', 'textarea' => 'Forneça uma descrição detalhada.', 'select' => 'Selecione uma das opções: ' . implode(', ', $field['options'] ?? []), default => 'Preencha com a informação solicitada.' };
        ?>
        <li><span class="font-semibold"><?= htmlspecialchars($field['label']) ?>:</span><span class="text-gray-600 ml-1"><?= $guideline ?></span></li>
        <?php endforeach; ?>
        </ul></div></div>
        <?php endforeach; ?>
        </div></div>
        <?php
    }
}

if (!function_exists('render_custom_templates_page')) {
    function render_custom_templates_page($data) {
        render_management_page('Modelos Personalizados', 'Modelo', array_filter($data['test_templates'], fn($t) => $t['is_custom']),
            function($t) { echo '<div class="bg-gray-50 p-3 rounded-lg font-semibold">' . htmlspecialchars($t['name']) . '</div>'; },
            function() { ?>
                <form method="POST" id="form-custom-template"><input type="hidden" name="action" value="add_custom_template"><input type="text" name="template[name]" placeholder="Nome do Modelo" required class="w-full p-3 bg-gray-50 border rounded-lg mb-4"><textarea name="template[description]" placeholder="Descrição do Modelo" required class="w-full p-3 bg-gray-50 border rounded-lg mb-4"></textarea>
                <div class="border-t pt-4"><h4 class="font-semibold">Campos do Formulário</h4><div id="fields-container" class="space-y-2 mt-2"></div><button type="button" id="add-field-btn" class="mt-2 text-sm text-cyan-600">+ Adicionar Campo</button></div>
                <input type="hidden" name="formFields" id="form-fields-json">
                <button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg font-bold mt-4">Salvar Modelo</button></form>
                <script>
                    const fieldsContainer = document.getElementById('fields-container'); let fields = [];
                    document.getElementById('add-field-btn').addEventListener('click', () => {
                        const fieldId = `field_${Date.now()}`;
                        const fieldHtml = `<div id="${fieldId}" class="grid grid-cols-1 md:grid-cols-2 gap-2 p-2 border rounded-lg mt-2">
                            <input type="text" placeholder="Nome do Campo (ex: 'Resposta foi clara?')" oninput="updateField('${fieldId}', 'label', this.value)" class="w-full p-2 bg-white border rounded text-sm">
                            <select onchange="updateField('${fieldId}', 'type', this.value)" class="w-full p-2 bg-white border rounded text-sm"><option value="text">Texto Curto</option><option value="textarea">Texto Longo</option><option value="tri-state">Sim/Não/N/A</option></select></div>`;
                        fieldsContainer.insertAdjacentHTML('beforeend', fieldHtml);
                        fields.push({ id: fieldId, name: `custom_${fieldId}`, label: '', type: 'text' });
                    });
                    function updateField(id, prop, value) {
                        const field = fields.find(f => f.id === id); if(field) field[prop] = value;
                    }
                    document.getElementById('form-custom-template').addEventListener('submit', (e) => {
                        document.getElementById('form-fields-json').value = JSON.stringify(fields.map(({id, ...rest}) => rest));
                    });
                </script>
            <?php }
        );
    }
}

if (!function_exists('render_error_page')) {
    function render_error_page($title, $message) {
        render_header("Erro");
        ?>
        <div class="min-h-screen flex items-center justify-center bg-gray-100 px-4">
            <div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-lg text-center">
                <h1 class="text-3xl font-bold text-red-600 mb-2"><?= htmlspecialchars($title) ?></h1>
                <p class="text-gray-600 text-left"><?= $message ?></p>
            </div>
        </div>
        <?php
        render_footer();
    }
}


// =================================================================
// Bloco de Execução Principal
// =================================================================

// Processa ações e popula o banco de dados se necessário
seed_initial_templates();
handle_post_requests();

// Roteamento
$page = $_GET['page'] ?? 'dashboard';
if ($page === 'logout') {
    logout();
}
if (!is_logged_in() && $page !== 'login') {
    header('Location: index.php?page=login');
    exit;
}

// Busca os dados atualizados para a renderização
$all_data = get_data();

// Mapa de páginas e permissões
$pages = [
    'dashboard' => ['renderer' => 'render_dashboard_page', 'roles' => ['admin', 'tester', 'client']],
    'client-management' => ['renderer' => 'render_client_management_page', 'roles' => ['admin']],
    'project-management' => ['renderer' => 'render_project_management_page', 'roles' => ['admin']],
    'user-management' => ['renderer' => 'render_user_management_page', 'roles' => ['admin']],
    'test-management' => ['renderer' => 'render_test_management_page', 'roles' => ['admin', 'tester']],
    'reports' => ['renderer' => 'render_reports_page', 'roles' => ['admin', 'tester', 'client']],
    'test-guidelines' => ['renderer' => 'render_test_guidelines_page', 'roles' => ['admin', 'tester', 'client']],
    'custom-templates' => ['renderer' => 'render_custom_templates_page', 'roles' => ['admin']],
];

// Renderiza a página correta
if ($page === 'login') {
    render_login_page($all_data);
} elseif (isset($pages[$page]) && has_permission($pages[$page]['roles'])) {
    render_app_layout($page, $pages[$page]['renderer'], $all_data);
} else {
    // Redireciona para o dashboard se a página for inválida ou sem permissão
    render_app_layout('dashboard', 'render_dashboard_page', $all_data);
}
?>
```
Most up-to-date Immersive Artifact for "sql_admin_insert" is:

```sql
-- Substitua os valores de exemplo pelos seus dados.
-- O mais importante é substituir 'COLE_O_HASH_GERADO_AQUI' pelo resultado do passo 1.

INSERT INTO `users` (`name`, `email`, `password_hash`, `role`) 
VALUES 
('Administrador', 'admin@exemplo.com', 'COLE_O_HASH_GERADO_AQUI', 'admin');

