<?php
$config = include __DIR__ . '/config.php';

$host = $config['host'];
$db   = $config['db'];
$user = $config['user'];
$pass = $config['pass'];
$dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";

$current_version = '0.0.1';
$lock_file = sys_get_temp_dir() . '/update_check.lock';

function checkForUpdates($current_version) {
    $update_file_url = 'https://raw.githubusercontent.com/13-GG/logs-update/main/logs_update.json';
    global $lock_file;

    if (file_exists($lock_file)) {
        $last_check = filemtime($lock_file);
        if (time() - $last_check < 60) {
            return ['update_available' => false, 'reason' => 'recently_checked'];
        }
    }

    touch($lock_file);

    try {
        $context = stream_context_create([
            'http' => ['timeout' => 10, 'user_agent' => 'auto-update/1.0'],
            'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
        ]);

        $update_info = file_get_contents($update_file_url, false, $context);
        $update_data = json_decode($update_info, true);

        if (!$update_data || !isset($update_data['LOGS_VERSION'], $update_data['UPDATE_URL'])) {
            return ['update_available' => false, 'reason' => 'invalid_data'];
        }

        $new_version = $update_data['LOGS_VERSION'];

        if (version_compare($new_version, $current_version, '>')) {
            $raw_url = str_replace('https://github.com/', 'https://raw.githubusercontent.com/', $update_data['UPDATE_URL']);
            $raw_url = str_replace('/blob/', '/', $raw_url);

            $new_file_content = file_get_contents($raw_url, false, $context);
            if ($new_file_content) {
                $backup_dir = __DIR__ . '/backups/' . date('Y-m-d_H-i-s');
                if (!is_dir($backup_dir)) {
                    mkdir($backup_dir, 0777, true);
                }

                $backup_php = $backup_dir . '/backup.php';
                copy(__FILE__, $backup_php);

                foreach (glob(__DIR__ . '/*.txt') as $txt_file) {
                    copy($txt_file, $backup_dir . '/' . basename($txt_file));
                }

                if (file_put_contents(__FILE__, $new_file_content) !== false) {
                    file_put_contents(
                        __DIR__ . '/update_log.txt',
                        date('Y-m-d H:i:s') . " - Updated from $current_version to $new_version\n",
                        FILE_APPEND
                    );
                    return [
                        'update_available' => true,
                        'updated' => true,
                        'old_version' => $current_version,
                        'new_version' => $new_version
                    ];
                }
            }
        }

        return [
            'update_available' => false,
            'reason' => 'up_to_date',
            'current' => $current_version,
            'latest' => $new_version
        ];
    } catch (Exception $e) {
        file_put_contents(
            __DIR__ . '/update_errors.txt',
            date('Y-m-d H:i:s') . " - Update error: " . $e->getMessage() . "\n",
            FILE_APPEND
        );
        return ['update_available' => false, 'reason' => 'error', 'error' => $e->getMessage()];
    }
}

checkForUpdates($current_version);

header('Content-Type: application/json; charset=utf-8');

$allowed_ips = ['IP'];
$client_ip = $_SERVER['REMOTE_ADDR'];

if (!in_array($client_ip, $allowed_ips)) {
    http_response_code(403);
    echo json_encode(['error' => 'Доступ запрещен. Ваш IP: ' . $client_ip]);
    exit;
}

$lock_dir = sys_get_temp_dir() . '/rate_limit/';
if (!file_exists($lock_dir)) mkdir($lock_dir, 0755, true);

$ip_hash = md5($client_ip);
$lock_file = $lock_dir . $ip_hash . '.lock';

$max_requests = 10;
$time_window = 10;
$ban_time = 20;

$current_data = ['count' => 0, 'first' => time(), 'banned' => 0];
if (file_exists($lock_file)) {
    $content = file_get_contents($lock_file);
    $current_data = json_decode($content, true) ?: $current_data;
}

if (time() < $current_data['banned']) {
    $remaining = $current_data['banned'] - time();
    http_response_code(429);
    header('Retry-After: ' . $remaining);
    echo json_encode(['error' => 'IP заблокирован. Попробуйте через ' . $remaining . ' сек']);
    exit;
}

if (time() - $current_data['first'] > $time_window) {
    $current_data['count'] = 0;
    $current_data['first'] = time();
}

$current_data['count']++;

if ($current_data['count'] > $max_requests) {
    $current_data['banned'] = time() + $ban_time;
    file_put_contents($lock_file, json_encode($current_data), LOCK_EX);

    http_response_code(429);
    header('Retry-After: ' . $ban_time);
    echo json_encode(['error' => 'Слишком много запросов. IP заблокирован на 20 секунд']);
    exit;
}

file_put_contents($lock_file, json_encode($current_data), LOCK_EX);

usleep(100000);
set_time_limit(5);
ini_set('memory_limit', '32M');

try {
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);

    $sql = "SELECT * FROM accounts WHERE Admin > 0";
    $adminsStmt = $pdo->query($sql);

    $adminsBase = [];
    while ($row = $adminsStmt->fetch()) {
        $adminsBase[$row['NickName']] = [
            'level' => $row['Admin'] ?? 0,
            'post' => $row['AdminTag'] ?? '',
            'total_seconds' => 0,
            'bans_count' => 0,
            'unbans_count' => 0,
            'rep_count' => 0,
            'warns_count' => 0,
            'mutes_count' => 0,
            'jail_count' => 0,
            'kick_count' => 0,
            'rmute_count' => 0,
            'thanks_count' => 0,
            'ot_count' => 0,
            'joins_count' => 0,
            'exit_count' => 0,
            'last_join' => null,
            'current_login' => null,
            'daily_online' => array_fill_keys(
                ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'],
                0
            ),
            'daily_ot' => array_fill_keys(
                ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'],
                0
            )
        ];
    }

    if (empty($adminsBase)) {
        echo json_encode([]);
        exit;
    }

    function processLogs($pdo, $whereClause, $adminsBase) {
        $sql = "SELECT Text, Date FROM logs WHERE $whereClause ORDER BY Date ASC";
        $stmt = $pdo->query($sql);
        $rows = $stmt->fetchAll();

        $admins = $adminsBase;

        foreach ($rows as $row) {
            $clean = strip_tags($row['Text']);

            // --- БАНЫ ---
            if (preg_match('/Администратор\s+(\S+)\s+забанил игрока\s+(\S+)/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['bans_count']++;
            }

            // --- РАЗБАНЫ ---
            if (preg_match('/Администратор\s+(\S+)\s+разбанил игрока\s+(\S+)/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['unbans_count']++;
            }

            // --- ДЕМОРГАН ---
            if (preg_match('/Администратор\s+(\S+)\s+посадил игрока\s+(\S+)/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['jail_count']++;
            }

            // --- КИК ---
            if (preg_match('/Администратор\s+(\S+)\s+кикнул игрока\s+(\S+)/u', $clean, $m) ||
                preg_match('/Администратор\s+(\S+)\s+тихо кикнул игрока\s+(\S+)/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['kick_count']++;
            }

            // --- МУТ РЕПОРТА ---
            if (preg_match('/Администратор\s+(\S+)\s+заблокировал репорт/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['ot_count']++;
            }

            // --- ОТВЕТ РЕПОРТ ---
            if (preg_match('/Администратор\s+(\S+)\s+ответил на репорт/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) {
                    $admins[$admin]['rmute_count']++;
                    $admins[$admin]['rep_count']++;

                    $day = strtolower(date('l', strtotime($row['Date'])));
                    if (isset($admins[$admin]['daily_ot'][$day])) {
                        $admins[$admin]['daily_ot'][$day]++;
                    }
                }
            }

            // --- ПОХВАЛА ---
            if (preg_match('/отблагодарил администратора\s+(\S+)\s+/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['thanks_count']++;
            }

            // --- ВАРНЫ ---
            if (preg_match('/Администратор\s+(\S+)\s+выдал предупреждение/u', $clean, $m) ||
                preg_match('/Администратор\s+(\S+)\s+установил в оффлайне/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['warns_count']++;
            }

            // --- МУТЫ ---
            if (preg_match('/Администратор\s+(\S+)\s+заглушил игрока/u', $clean, $m) ||
                preg_match('/Администратор\s+(\S+)\s+тихо заглушил игрока/u', $clean, $m)) {
                $admin = $m[1];
                if (isset($admins[$admin])) $admins[$admin]['mutes_count']++;
            }

            // --- ВХОДЫ / ВЫХОДЫ ---
            if (preg_match('/Игрок\s+(\S+)/u', $clean, $m1)) {
                $username = $m1[1];
                if (!isset($admins[$username])) continue;

                if (strpos($clean, 'вошёл') !== false) {
                    $admins[$username]['current_login'] = strtotime($row['Date']);
                    $admins[$username]['joins_count']++;
                    $admins[$username]['last_join'] = $row['Date'];
                } elseif (strpos($clean, 'вышел') !== false && !empty($admins[$username]['current_login'])) {
                    $login_time = $admins[$username]['current_login'];
                    $logout_time = strtotime($row['Date']);
                    $seconds = max(0, $logout_time - $login_time);
                    $admins[$username]['total_seconds'] += $seconds;
                    $admins[$username]['exit_count']++;
                    $admins[$username]['current_login'] = null;

                    $day = strtolower(date('l', $login_time));
                    if (isset($admins[$username]['daily_online'][$day])) {
                        $admins[$username]['daily_online'][$day] += $seconds;
                    }
                }
            }
        }

        $now = time();
        foreach ($admins as $username => &$info) {
            if (!empty($info['current_login'])) {
                $seconds = max(0, $now - $info['current_login']);
                $info['total_seconds'] += $seconds;

                $day = strtolower(date('l', $info['current_login']));
                if (isset($info['daily_online'][$day])) {
                    $info['daily_online'][$day] += $seconds;
                }

                $info['current_login'] = null;
            }
        }
        unset($info);

        $result = [];
        foreach ($admins as $username => $info) {
            $total = $info['total_seconds'];
            $h = floor($total / 3600);
            $m = floor(($total % 3600) / 60);
            $s = $total % 60;

            $daily_fmt = [];
            foreach ($info['daily_online'] as $day => $sec) {
                $dh = floor($sec / 3600);
                $dm = floor(($sec % 3600) / 60);
                $ds = $sec % 60;
                $daily_fmt["online_{$day}"] = sprintf("%02d:%02d:%02d", $dh, $dm, $ds);
            }
            foreach ($info['daily_ot'] as $day => $count) {
                $daily_fmt["ot_{$day}"] = $count;
            }
            $ot_total = array_sum($info['daily_ot']);

            $result[] = array_merge([
                'username' => $username,
                'lvl' => $info['level'],
                'post' => $info['post'],
                'total_week' => sprintf("%02d:%02d:%02d", $h, $m, $s),
                'bans_count' => $info['bans_count'],
                'unbans_count' => $info['unbans_count'],
                'rep_count' => $info['rep_count'],
                'warns_count' => $info['warns_count'],
                'mutes_count' => $info['mutes_count'],
                'jail_count' => $info['jail_count'],
                'rmute_count' => $info['rmute_count'],
                'thanks_count' => $info['thanks_count'],
                'ot_count' => $ot_total,
                'joins_count' => $info['joins_count'],
                'exit_count' => $info['exit_count'],
                'last_join' => $info['last_join'] ?? 'Не было заходов'
            ], $daily_fmt);
        }

        return $result;
    }

    $currentWeekRangeStart = date('Y-m-d', strtotime('monday this week'));
    $currentWeekRangeEnd   = date('Y-m-d', strtotime('sunday this week'));

    $currentWeek = processLogs(
        $pdo,
        "Date >= '$currentWeekRangeStart' AND Date <= '$currentWeekRangeEnd'",
        $adminsBase
    );

    $lastWeekRangeStart = date('Y-m-d', strtotime('monday last week'));
    $lastWeekRangeEnd   = date('Y-m-d', strtotime('sunday last week'));

    $lastWeek = processLogs(
        $pdo,
        "Date >= '$lastWeekRangeStart' AND Date <= '$lastWeekRangeEnd'",
        $adminsBase
    );

    echo json_encode([
        'version' => $current_version,
        'current_week' => $currentWeek,
        'last_week' => $lastWeek
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
