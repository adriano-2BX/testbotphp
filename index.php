<?php
// =================================================================
// Bloco de Configuração e Definição de Classes
// =================================================================

// --- CONFIGURAÇÃO DO BANCO DE DADOS E CONSTANTES ---
define('DB_URL', 'mysql://mysql:bc86348b3cfea8e64566@lab_mysql:3306/testbot');

const PRESET_TESTS = [
    ['id' => 'GREETING', 'name' => "Saudação e Despedida", 'description' => "Verifica se o bot saúda, se apresenta e se despede corretamente.", 'formFields' => [['name' => 'didGreet', 'label' => 'Bot iniciou com uma saudação?', 'type' => 'tri-state'], ['name' => 'identifiedUser', 'label' => 'Identificou o nome do utilizador?', 'type' => 'tri-state'], ['name' => 'offeredHelp', 'label' => 'Ofereceu ajuda ou apresentou-se?', 'type' => 'tri-state'], ['name' => 'didFarewell', 'label' => 'Despediu-se cordialmente no final?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações Adicionais', 'type' => 'textarea']]],
    ['id' => 'INTENT_RECOGNITION', 'name' => "Reconhecimento de Intenção", 'description' => "Avalia a capacidade do bot de compreender a intenção principal do utilizador.", 'formFields' => [['name' => 'userQuestion', 'label' => 'Pergunta/Frase do Utilizador', 'type' => 'textarea'], ['name' => 'expectedIntent', 'label' => 'Intenção Esperada', 'type' => 'text'], ['name' => 'botResponse', 'label' => 'Resposta do Bot', 'type' => 'textarea'], ['name' => 'result', 'label' => 'Resultado', 'type' => 'select', 'options' => ['Correto', 'Incorreto', 'Parcialmente Correto']]]],
    ['id' => 'CONTEXT_MANAGEMENT', 'name' => "Gestão de Contexto", 'description' => "Avalia a capacidade do bot de manter o contexto em múltiplos turnos de conversa.", 'formFields' => [['name' => 'initialQuery', 'label' => 'Pergunta Inicial', 'type' => 'textarea'], ['name' => 'followUpQuery', 'label' => 'Pergunta de Continuação (sem repetir o contexto)', 'type' => 'textarea'], ['name' => 'contextKept', 'label' => 'O bot manteve o contexto?', 'type' => 'tri-state'], ['name' => 'notes', 'label' => 'Observações de Contexto', 'type' => 'textarea']]],
    ['id' => 'PROMPT_INJECTION', 'name' => "Segurança: Injeção de Prompt", 'description' => "Tenta manipular o bot com instruções maliciosas para ignorar as suas diretrizes originais.", 'formFields' => [['name' => 'injectionAttempt', 'label' => 'Tentativa de Injeção de Prompt', 'type' => 'textarea'], ['name' => 'wasResisted', 'label' => 'O bot resistiu à injeção?', 'type' => 'tri-state'], ['name' => 'botFinalResponse', 'label' => 'Resposta Final do Bot', 'type' => 'textarea']]],
];

/**
 * Classe para gerir sessões na base de dados.
 */
class DatabaseSessionHandler implements SessionHandlerInterface {
    private $db;
    private $ready = false;

    public function open($savePath, $sessionName): bool {
        $db_parts = parse_url(DB_URL);
        $db_host = $db_parts['host'] ?? null;
        $db_user = $db_parts['user'] ?? null;
        $db_pass = $db_parts['pass'] ?? null;
        $db_name = isset($db_parts['path']) ? ltrim($db_parts['path'], '/') : null;
        $db_port = $db_parts['port'] ?? 3306;

        $db = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);
        if ($db && !$db->connect_error) {
            $this->db = $db;
            $this->ready = true;
            return true;
        }
        error_log('DatabaseSessionHandler: Não foi possível conectar ao banco de dados.');
        return false;
    }

    public function close(): bool {
        if ($this->ready && $this->db) {
            return $this->db->close();
        }
        return true;
    }

    public function read($id): string {
        if (!$this->ready) return '';
        $stmt = $this->db->prepare("SELECT data FROM sessions WHERE id = ?");
        $stmt->bind_param('s', $id);
        if ($stmt->execute()) {
            $result = $stmt->get_result();
            if ($row = $result->fetch_assoc()) {
                return $row['data'] ?? '';
            }
        }
        return '';
    }

    public function write($id, $data): bool {
        if (!$this->ready) return false;
        $access = time();
        $stmt = $this->db->prepare("REPLACE INTO sessions (id, access, data) VALUES (?, ?, ?)");
        $stmt->bind_param('sis', $id, $access, $data);
        return $stmt->execute();
    }

    public function destroy($id): bool {
        if (!$this->ready) return false;
        $stmt = $this->db->prepare("DELETE FROM sessions WHERE id = ?");
        $stmt->bind_param('s', $id);
        return $stmt->execute();
    }

    #[\ReturnTypeWillChange]
    public function gc($maxlifetime): int|false {
        if (!$this->ready) return false;
        $old = time() - $maxlifetime;
        $stmt = $this->db->prepare("DELETE FROM sessions WHERE access < ?");
        $stmt->bind_param('i', $old);
        $stmt->execute();
        return $stmt->affected_rows;
    }
}

// --- INICIALIZAÇÃO DA SESSÃO COM O GESTOR DE BASE DE DADOS ---
$handler = new DatabaseSessionHandler();
session_set_save_handler($handler, true);
session_start();

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
                     render_error_page( "Erro de Conexão", "Não foi possível conectar ao banco de dados.");
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
                return true;
            }
        }
        return false;
    }
}
if (!function_exists('logout')) { function logout() { session_unset(); session_destroy(); header('Location: index.php?page=login'); exit; } }
if (!function_exists('is_logged_in')) { function is_logged_in() { return isset($_SESSION['user']) && is_array($_SESSION['user']); } }
if (!function_exists('get_current_user')) { function get_current_user() { return $_SESSION['user'] ?? null; } }
if (!function_exists('has_permission')) { function has_permission($roles) { $user = get_current_user(); if (!$user) return false; return in_array($user['role'], (array)$roles, true); } }
if (!function_exists('handle_post_requests')) {
    function handle_post_requests() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        
        $conn = get_db_connection();
        $action = $_POST['action'] ?? '';
        $user = get_current_user();
        $redirect_url = $_SERVER['REQUEST_URI']; // Padrão

        try {
            switch ($action) {
                case 'login':
                    if (login($_POST['email'], $_POST['password'])) {
                        $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Login bem-sucedido!'];
                        $redirect_url = 'index.php?page=dashboard';
                    } else {
                        $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Credenciais inválidas.'];
                        $redirect_url = 'index.php?page=login';
                    }
                    break;
                case 'add_client': if (has_permission('admin')) { $stmt = $conn->prepare("INSERT INTO clients (name) VALUES (?)"); $stmt->bind_param("s", $_POST['name']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Cliente adicionado com sucesso!']; } break;
                case 'add_project': if (has_permission('admin')) { $p = $_POST['project']; $stmt = $conn->prepare("INSERT INTO projects (client_id, name, whatsapp_number, description, objective) VALUES (?, ?, ?, ?, ?)"); $stmt->bind_param("issss", $p['clientId'], $p['name'], $p['whatsappNumber'], $p['description'], $p['objective']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Projeto adicionado com sucesso!']; } break;
                case 'add_user': if (has_permission('admin')) { $u = $_POST['user']; $password_hash = password_hash($u['password'], PASSWORD_DEFAULT); $stmt = $conn->prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)"); $stmt->bind_param("ssss", $u['name'], $u['email'], $password_hash, $u['role']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Utilizador adicionado com sucesso!']; } break;
                case 'add_test': if (has_permission('admin')) { $t = $_POST['test']; $test_id = 'TEST-' . time(); $custom_fields_json = $_POST['customFields'] ?? '[]'; $stmt = $conn->prepare("INSERT INTO test_cases (id, project_id, template_id, assigned_to_id, custom_fields) VALUES (?, ?, ?, ?, ?)"); $stmt->bind_param("sisis", $test_id, $t['projectId'], $t['typeId'], $t['assignedTo'], $custom_fields_json); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Caso de teste criado com sucesso!']; } break;
                case 'execute_test': if (has_permission('tester')) { $testCaseId = $_POST['test_case_id']; $resultsJson = json_encode($_POST['results']); $reportId = 'REP-' . time(); $executionDate = date('Y-m-d H:i:s'); $conn->begin_transaction(); $stmt_update = $conn->prepare("UPDATE test_cases SET status = 'completed', paused_state = NULL WHERE id = ?"); $stmt_update->bind_param("s", $testCaseId); $stmt_update->execute(); $stmt_insert = $conn->prepare("INSERT INTO reports (id, test_case_id, tester_id, execution_date, results) VALUES (?, ?, ?, ?, ?)"); $stmt_insert->bind_param("ssiss", $reportId, $testCaseId, $user['id'], $executionDate, $resultsJson); $stmt_insert->execute(); $conn->commit(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Teste concluído e relatório gerado!']; } break;
                case 'pause_test': if (has_permission('tester')) { $pausedStateJson = json_encode($_POST['results']); $stmt = $conn->prepare("UPDATE test_cases SET status = 'paused', paused_state = ? WHERE id = ?"); $stmt->bind_param("ss", $pausedStateJson, $_POST['test_case_id']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Teste pausado com sucesso.']; } break;
                case 'resume_test': if (has_permission('tester')) { $stmt = $conn->prepare("UPDATE test_cases SET status = 'pending' WHERE id = ?"); $stmt->bind_param("s", $_POST['test_case_id']); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'info', 'message' => 'Teste retomado.']; } break;
                case 'add_custom_template': if (has_permission('admin')) { $t = $_POST['template']; $template_id = 'CUSTOM-' . time(); $form_fields_json = $_POST['formFields'] ?? '[]'; $stmt = $conn->prepare("INSERT INTO test_templates (id, name, description, form_fields, is_custom) VALUES (?, ?, ?, ?, 1)"); $stmt->bind_param("ssss", $template_id, $t['name'], $t['description'], $form_fields_json); $stmt->execute(); $_SESSION['flash_message'] = ['type' => 'success', 'message' => 'Modelo personalizado criado com sucesso!']; } break;
            }
        } catch (mysqli_sql_exception $e) {
            error_log("SQL Error: " . $e->getMessage());
            if ($conn->in_transaction) { $conn->rollback(); }
            $_SESSION['flash_message'] = ['type' => 'error', 'message' => 'Ocorreu um erro ao processar a sua solicitação.'];
        }

        header('Location: ' . $redirect_url);
        exit;
    }
}
// Copie e cole todas as suas funções de ÍCONES e de RENDERIZAÇÃO aqui.
// Elas não precisam de alteração.
// Exemplo:
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
if (!function_exists('render_header')) { function render_header($title) { ?><!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" /><title><?= htmlspecialchars($title) ?> - TestBot Manager</title><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script><script src="https://cdn.tailwindcss.com"></script><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"><style>body { font-family: 'Inter', sans-serif; overscroll-behavior-y: contain; } .content-scrollable::-webkit-scrollbar { display: none; } .content-scrollable { -ms-overflow-style: none; scrollbar-width: none; } details > summary { list-style: none; } details > summary::-webkit-details-marker { display: none; }</style></head><body class="bg-gray-100 text-gray-900 min-h-screen antialiased"><?php } }
if (!function_exists('render_footer')) { function render_footer() { ?></body></html><?php } }
if (!function_exists('render_flash_message')) { function render_flash_message() { if (isset($_SESSION['flash_message'])) { $flash = $_SESSION['flash_message']; $colors = [ 'success' => 'bg-green-100 border-green-500 text-green-700', 'error' => 'bg-red-100 border-red-500 text-red-700', 'info' => 'bg-blue-100 border-blue-500 text-blue-700' ]; $colorClass = $colors[$flash['type']] ?? $colors['info']; echo '<div class="' . $colorClass . ' border-l-4 p-4 mb-4 rounded-r-lg" role="alert"><p>' . htmlspecialchars($flash['message']) . '</p></div>'; unset($_SESSION['flash_message']); } } }
if (!function_exists('render_app_layout')) { function render_app_layout($page, callable $content_renderer, $all_data) { $user = get_current_user(); if (!$user) { logout(); return; } $pageTitles = ['dashboard' => "Dashboard", 'test-management' => "Gerir Testes", 'user-management' => "Gerir Utilizadores", 'reports' => "Relatórios", 'client-management' => "Gerir Clientes", 'project-management' => "Gerir Projetos", 'test-guidelines' => "Orientações de Teste", 'custom-templates' => "Modelos Personalizados"]; $title = $pageTitles[$page] ?? 'Detalhes'; render_header($title); $navItems = [ 'admin' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Clientes", 'path' => "client-management", 'icon' => BuildingIcon()],['name' => "Projetos", 'path' => "project-management", 'icon' => FolderIcon()],['name' => "Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Utilizadores", 'path' => "user-management", 'icon' => UsersIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Modelos", 'path' => "custom-templates", 'icon' => BeakerIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'tester' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Meus Testes", 'path' => "test-management", 'icon' => ClipboardListIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], 'client' => [['name' => "Dashboard", 'path' => "dashboard", 'icon' => HomeIcon()],['name' => "Relatórios", 'path' => "reports", 'icon' => FileTextIcon()],['name' => "Orientações", 'path' => "test-guidelines", 'icon' => HelpCircleIcon()]], ]; $userNav = $navItems[$user['role']] ?? []; ?> <div class="h-screen w-screen flex flex-col sm:flex-row bg-gray-100"> <div class="hidden sm:flex flex-col w-64 bg-white border-r border-gray-200 p-4"> <h1 class="text-2xl font-bold text-cyan-600 mb-10 px-2">TestBot</h1> <nav class="flex-1 space-y-2"><?php foreach ($userNav as $item): $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="w-full flex items-center gap-3 text-left py-2.5 px-4 rounded-lg transition-colors text-base font-semibold <?= $isActive ? 'bg-cyan-500 text-white shadow-sm' : 'text-gray-600 hover:bg-gray-100' ?>"><?= $item['icon']('class="w-5 h-5"') ?><?= htmlspecialchars($item['name']) ?></a><?php endforeach; ?></nav> <div class="pt-6 border-t border-gray-200"><p class="text-sm font-semibold text-gray-800"><?= htmlspecialchars($user['name']) ?></p><p class="text-xs text-gray-500 capitalize"><?= htmlspecialchars($user['role']) ?></p></div> </div> <div class="flex-1 flex flex-col overflow-hidden"> <header class="bg-white/80 backdrop-blur-lg border-b border-gray-200 w-full z-10"><div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8"><div class="flex items-center justify-between h-16"><h1 class="text-lg font-bold text-gray-800"><?= htmlspecialchars($title) ?></h1><a href="index.php?page=logout" class="hidden sm:flex items-center gap-2 text-sm font-semibold text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-5 h-5"') ?>Sair</a></div></div></header> <main class="flex-1 overflow-y-auto content-scrollable p-4 sm:p-6 pb-24 sm:pb-6"><?php render_flash_message(); $content_renderer($all_data); ?></main> <nav class="sm:hidden fixed bottom-0 left-0 right-0 bg-white/80 backdrop-blur-lg border-t border-gray-200 z-20"><div class="flex justify-around items-center h-16"><?php foreach ($userNav as $item): if(count($userNav) > 4 && $item['name'] === 'Orientações') continue; $isActive = $page === $item['path']; ?><a href="index.php?page=<?= $item['path'] ?>" class="flex flex-col items-center justify-center w-full h-full transition-colors <?= $isActive ? 'text-cyan-500' : 'text-gray-500 hover:text-cyan-500' ?>"><?= $item['icon']('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium"><?= htmlspecialchars($item['name']) ?></span></a><?php endforeach; ?><a href="index.php?page=logout" class="flex flex-col items-center justify-center w-full h-full text-gray-500 hover:text-red-500"><?= LogOutIcon('class="w-6 h-6 mb-1"') ?><span class="text-xs font-medium">Sair</span></a></div></nav> </div> </div> <?php render_footer(); } }
if (!function_exists('render_login_page')) { function render_login_page() { render_header('Login'); ?><div class="min-h-screen flex items-center justify-center bg-gray-100 px-4"><div class="bg-white p-8 rounded-2xl shadow-md w-full max-w-sm"><h1 class="text-3xl font-bold text-gray-800 text-center mb-2">TestBot</h1><p class="text-center text-gray-500 mb-8">Manager Login</p><?php render_flash_message(); ?><form method="POST" action="index.php"><input type="hidden" name="action" value="login"><div class="mb-4"><label for="email" class="text-sm font-bold text-gray-600 mb-1 block">Email</label><input id="email" name="email" type="email" autocomplete="username" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><div class="mb-6"><label for="password" class="text-sm font-bold text-gray-600 mb-1 block">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required class="w-full p-3 bg-gray-50 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500 transition"/></div><button type="submit" class="w-full bg-cyan-500 text-white p-3 rounded-lg hover:bg-cyan-600 transition duration-200 font-bold">Entrar</button></form></div></div><?php render_footer(); } }
if (!function_exists('render_dashboard_page')) { function render_dashboard_page($data) { $user = get_current_user(); if (!$user) { logout(); return; } $firstName = explode(' ', $user['name'])[0]; ?> <div class="space-y-6"><h2 class="text-2xl font-bold text-gray-800">Olá, <?= htmlspecialchars($firstName) ?>!</h2></div> <?php } }
if (!function_exists('render_error_page')) { function render_error_page($title, $message) { render_header("Erro"); echo "<h1>$title</h1><p>$message</p>"; render_footer(); } }
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

handle_post_requests();

$page = $_GET['page'] ?? 'login';

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
    // Se a página não existe ou não tem permissão, redireciona para o dashboard
    header('Location: index.php?page=dashboard');
    exit;
}
?>
