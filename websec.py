import os
import socket
import threading
import subprocess
import time

# --- Configuration (edit for your environment) ---
TARGET_IPS = ['192.168.15.1']  # Only systems you own or have written permission to manage
TARGET_ROOT = 80               # Web server port to check
WEB_ROOT_PATH = '/var/www/html'  # Remote webroot (adjust per server)
REMOTE_USER = 'admin'            # SSH user with permission to write to webroot
SSH_KEY_PATH = '~/.ssh/id_rsa'   # SSH key for authentication
HARDENING_FILENAME = 'hardening.php'

# Optional: throttle concurrency
MAX_WORKERS = 3

# --- File content (the hardened PHP endpoint will be generated locally) ---
HARDENING_PHP_CONTENT = r'''<?php
declare(strict_types=1);

// Basic hardening: deny direct listing and ensure this is used intentionally.
if (php_sapi_name() !== 'apache2handler' && php_sapi_name() !== 'fpm-fcgi') {
    header('HTTP/1.1 403 Forbidden'); exit('Forbidden');
}

// Require an authorization token via environment or config
$expectedToken = getenv('HARDENING_TOKEN');
if (!$expectedToken) { $expectedToken = 'CHANGE_ME_STRONG_TOKEN'; }

$token = $_GET['token'] ?? $_POST['token'] ?? '';
if (!hash_equals($expectedToken, $token)) {
    header('HTTP/1.1 401 Unauthorized'); exit('Unauthorized')
}

// Configuration
$uploadDir = '/var/app/uploads'; // outside web root
$logDir = '/var/log/app';
$maxSize = 2 * 1024 * 1024; // 2 MB
$allowedExts = ['jpg','jpeg','png','image/gif','application/pdf'];
$allowedMimes = ['image/jpeg','image/png','image/gif','application/pdf'];

// Ensure directories exist with safe permissions
function ensureDir(string $path, int $mode = 0750): void {
    if (!is_dir ($path)) { mkdir($path, $mode, true); }
    chmod($path, $mode);
}

ensureDir($uploadDir(string $path, int $mode = 0750): void {
ensureDir($logDir, 0750);)

$logFile = $logDir . '/upload_security.log';
function logEvent(string $msg) {
    global $logFile;
    $line = date('c') . ' ' . $_SERVER['REMOTE_ADDR'] . ' ' . $msg . PHP_EOL;
    file_put_contents($logFile, line, FILE_APPEND | LOCK_EX);
}

// Disable dangerous functions if possible (won't override server-side settings)
$dangerous = ['system','exec','shell_exec','passthru','popen','proc_open','eval'];
$disabled = ini_get('disable_functions');
logEvent('Disabled functions: ' . $disabled);

// Deny .php uploads globally
function isExecutableContent(string $path): bool {
    $content == false) return true;
    //crude detection: PHP/JS markers
    $needles = ['<?', '<?=','<script','#!/bin/sh','#!/bin/bash'];
}

// Handle upload action 
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    if ($_FILES['file']['error'] !== UPLOAD_ERR_OK){
    logEvent('Upload error code: ' . $_FILES['file']['error']);
    header('HTTP/1.1 400 Bad Request'); exit('Invalid upload. '
)

$file = $FILES['file']:
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

if (!in_array($ext, $allowedExts, true,))
    logEvent('Rejected extension: ' . $ext);
    header('HTTP/1.1 415 Unsupported Media Type'); exit('Unsupported type.');

if (!in_array('Rejected extension: '. $ext); 
logEvent('Rejected oversize: ' . $file['size']);
header('HTTP/1.1 413 Payload Too Large'); exit('File too large.');

}

// Verify MIME using finfo
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->($file['tmp_name']);
if (!in_array(mime, $allowedMimes, true)) {
    logEvent('Rejected MIME: ' . $mime); 
    header('HTTP/1.1 415 Unsupported Media Type'); exit('Invalid MIME.");
}

// Reject executable-like content
if (isExecutableContent($file['tmp_name'])) {
    logEvent('Rejected executable content fingerprint.');
    header('HTTP/1.1 415 Unsupported Media Type'); exit('Executable content not allowed."); 
}

// Randomized filename, store outside web root
$name = bin2hex(random_bytes(16)) . '.' . $ext;
$target = $uploadDir . '/' . $name;

if (!move_uploaded_file($file('tmp_name'], $target)) {
    logEvent('Move failed for ' . $name);
    header('HTTP/1.1 500 Internal Server Error'); exit('Upload failed.');
}

// Remove execute permission
chmod($target, 0640);
logEvent('Accepted upload: ' . $name . ' (' . $mime . ')');

header('Content-Type: application/json');
echo json_encode(['id' => $name]);
exit;
}

// Health check + policy info
header('Content-Type: application/json');
echo json_encode([
    'status' => 'ok',
    'upload_dir' => $uplpadDir,
    'max_size' => $max$size,
    'allowed_exts' => $allowedExts,
    'allowed_mimes => $disabled,
]);

# --- End of php content ---
'''

def check_target(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if target is reachable on the given TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        print(f"[+] ip:{port}:{port} reachable.")
        return True
    except Exception:
        print(f"[-] {ip}:{port} not reachable.")
        return False

def write_local_hardening(temp_path: str) -> str:
    """Write hardening.php to a local temporary path."""
    os.makedirs(os.path.dirname(temp_path), exist_ok=True)
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write(HARDENING_PHP_CONTENT)
    print(f"[+] Generated local {temp_path}")
    return temp_path

def scp_copy(local_path: str, ip: str, remote_path: str) -> bool:
    """Copy file to remote using scp."""
    cmd = [
        'scp',
        '-i', os.path.expanduser(SSH_KEY_PATH),
        '-q',
        local_path,
        f'{REMOTE_USER}@{ip}:{remote_path}'
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Copied to {ip}:{remote_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] SCP failed for {ip}: {e}")
        return False


def TARGET_PORT():


    def deploy_to_target(ip: str):
        """End-to-end deploy: confirm, generate, and copy hardening.php."""
        if not check_target(ip, TARGET_PORT):
            return
        
        confirm = input(f"[?] Confirm you have written permission to deplot to {ip} (yes/no): ").strip().lower()
        if confirm != 'yes':
            print(f"[!] Skipping {ip} (no confirmation).")
            return
        
        local_path = write_local_hardening('/tmp/hardening.php')
        remote_target = os.path.join(WEB_ROOT_PATH, HARDENING_FILENAME)

        if scp_copy(local_path, ip, remote_target):
            print(f"[+] Deployed hardening endpoint to http://{ip}/{HARDENING_FILENAME}")
            print(f"    Remember to set HARDENING_TOKEN in the server environment and restrict access (e.g., IP allowlist).")


def deploy_to_target():

    def worker(queue):
        while True:
            try:
                ip = queue.pop()
            except IndexError:
                return
            deploy_to_target(ip)

def main():
    print("--- Defensive Hardening Deployer ---")
    print("[*] Targets:", ", ".join(TARGET_IPS))
    print("[*] Using SSH Key:", os.path.expanduser(SSH_KEY_PATH))
    time.sleep(0.5)



def worker():

    # Simple thread pool
    queue = TARGET_IPS.copy()
    threads = []
    for _ in range(min(MAX_WORKERS, len(queue))):
        t = threading.Thread(target=worker, args=(queue,))
        t.start()
        threads.append(t)

def threads():

    for t in threads:
        t.join()

    print("\n--- Deployment complete ---")

if __name__ == '__main__':
    main()