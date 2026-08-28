<?php
/**
 * Plugin Name: FVC Bridge
 * Description: Token-authenticated REST bridge + self-update channel for Find Vancouver Clinics.
 * Version: 1.1.0
 * Author: Ruben de la Cruz
 * Update URI: https://github.com/rubenjdelacruz1985-jpg/fvc-bridge
 */

if ( ! defined('ABSPATH') ) exit;

define('FVC_BRIDGE_VERSION',    '1.1.0');
define('FVC_BRIDGE_SLUG',       'fvc-bridge');
define('FVC_BRIDGE_BASENAME',   plugin_basename(__FILE__)); // fvc-bridge/fvc-bridge.php
define('FVC_BRIDGE_MANIFEST',   'https://github.com/rubenjdelacruz1985-jpg/fvc-bridge/releases/latest/download/manifest.json');
// A package URL is only trusted if it starts with this prefix (pinned to your repo's releases).
define('FVC_BRIDGE_PKG_PREFIX', 'https://github.com/rubenjdelacruz1985-jpg/fvc-bridge/releases/download/');

/* ============================================================
 *  Auth helpers
 * ============================================================ */

function fvc_bridge_ip() {
    return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '0.0.0.0';
}

// Read the Bearer token from the Authorization header, tolerating hosts that
// relocate it (SiteGround/Apache CGI puts it in REDIRECT_HTTP_AUTHORIZATION).
function fvc_bridge_bearer_token() {
    $auth = '';
    if ( ! empty($_SERVER['HTTP_AUTHORIZATION']) ) {
        $auth = $_SERVER['HTTP_AUTHORIZATION'];
    } elseif ( ! empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ) {
        $auth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    } elseif ( function_exists('getallheaders') ) {
        foreach ( getallheaders() as $k => $v ) {
            if ( strtolower($k) === 'authorization' ) { $auth = $v; break; }
        }
    }
    if ( preg_match('/Bearer\s+(.+)/i', $auth, $m) ) {
        return trim($m[1]);
    }
    return '';
}

// Permission callback: valid token + basic per-IP rate limit.
function fvc_bridge_require_token() {
    $ip = fvc_bridge_ip();
    $rl_key = 'fvc_bridge_rl_' . md5($ip);
    $count = (int) get_transient($rl_key);
    if ( $count > 60 ) { // 60 requests/minute/IP
        fvc_bridge_log('rate-limited', 'ip=' . $ip);
        return new WP_Error('rate_limited', 'Too many requests', array('status' => 429));
    }
    set_transient($rl_key, $count + 1, MINUTE_IN_SECONDS);

    $token = fvc_bridge_bearer_token();
    if ( $token ) {
        $hash = hash('sha256', $token);
        foreach ( get_option('fvc_bridge_tokens', array()) as $t ) {
            if ( ! empty($t['hash']) && hash_equals($t['hash'], $hash) ) {
                return true;
            }
        }
    }
    fvc_bridge_log('auth-failed', 'ip=' . $ip);
    return new WP_Error('unauthorized', 'Invalid or missing token', array('status' => 401));
}

/* ============================================================
 *  Audit log (last 100 events in an option ring buffer)
 * ============================================================ */

function fvc_bridge_log($action, $detail = '') {
    $log = get_option('fvc_bridge_log', array());
    if ( ! is_array($log) ) $log = array();
    $log[] = array(
        'time'   => current_time('mysql'),
        'action' => $action,
        'detail' => $detail,
        'ip'     => fvc_bridge_ip(),
    );
    if ( count($log) > 100 ) $log = array_slice($log, -100);
    update_option('fvc_bridge_log', $log, false);
}

/* ============================================================
 *  REST endpoints  (/wp-json/fvc-bridge/v1/...)
 * ============================================================ */

add_action('rest_api_init', function () {
    register_rest_route('fvc-bridge/v1', '/health', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_health',
    ));
    register_rest_route('fvc-bridge/v1', '/self-update', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_self_update',
    ));
    // Public: the front-end forms call this to check for an existing listing.
    register_rest_route('fvc-bridge/v1', '/check-duplicate', array(
        'methods'             => 'POST',
        'permission_callback' => '__return_true',
        'callback'            => 'fvc_bridge_rest_check_dup',
    ));
    // Token-gated: list stored submissions (for review tooling).
    register_rest_route('fvc-bridge/v1', '/submissions', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_submissions',
    ));
});

function fvc_bridge_rest_health() {
    $manifest = fvc_bridge_get_manifest(true);
    $latest   = ( $manifest && ! empty($manifest['version']) ) ? $manifest['version'] : null;
    return new WP_REST_Response(array(
        'ok'               => true,
        'plugin'           => FVC_BRIDGE_SLUG,
        'version'          => FVC_BRIDGE_VERSION,
        'latest_available' => $latest,
        'update_available' => ( $latest && version_compare($latest, FVC_BRIDGE_VERSION, '>') ),
        'wp'               => get_bloginfo('version'),
        'php'              => PHP_VERSION,
        'time'             => current_time('mysql'),
    ), 200);
}

function fvc_bridge_rest_self_update() {
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

    $before = FVC_BRIDGE_VERSION;

    // Force a fresh manifest + update check.
    delete_site_transient('fvc_bridge_manifest');
    wp_clean_plugins_cache(true);
    wp_update_plugins();

    $skin       = new WP_Ajax_Upgrader_Skin();
    $upgrader   = new Plugin_Upgrader($skin);
    $was_active = is_plugin_active(FVC_BRIDGE_BASENAME);
    $result     = $upgrader->upgrade(FVC_BRIDGE_BASENAME);

    if ( $was_active ) {
        activate_plugin(FVC_BRIDGE_BASENAME);
    }
    if ( function_exists('opcache_reset') ) {
        @opcache_reset();
    }

    // The running process still holds the OLD constant; read the new version from disk.
    $data  = get_plugin_data(WP_PLUGIN_DIR . '/' . FVC_BRIDGE_BASENAME, false, false);
    $after = ! empty($data['Version']) ? $data['Version'] : $before;

    if ( is_wp_error($result) ) {
        fvc_bridge_log('self-update-failed', $result->get_error_message());
        return new WP_REST_Response(array('ok' => false, 'from' => $before, 'error' => $result->get_error_message()), 500);
    }
    if ( $result === false || $result === null ) {
        fvc_bridge_log('self-update-noop', 'from=' . $before);
        return new WP_REST_Response(array('ok' => true, 'from' => $before, 'to' => $after, 'note' => 'already up to date'), 200);
    }

    fvc_bridge_log('self-update', "from=$before to=$after");
    return new WP_REST_Response(array('ok' => true, 'from' => $before, 'to' => $after), 200);
}

/* ============================================================
 *  Self-update channel (WordPress "Update URI" mechanism)
 * ============================================================ */

function fvc_bridge_get_manifest($force = false) {
    if ( ! $force ) {
        $cached = get_site_transient('fvc_bridge_manifest');
        if ( $cached !== false ) return $cached;
    }
    $res = wp_remote_get(FVC_BRIDGE_MANIFEST, array('timeout' => 15));
    if ( is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200 ) {
        return false;
    }
    $body = wp_remote_retrieve_body($res);
    $body = preg_replace('/^\xEF\xBB\xBF/', '', $body); // tolerate a leading UTF-8 BOM
    $data = json_decode($body, true);
    if ( ! is_array($data) ) $data = false;
    set_site_transient('fvc_bridge_manifest', $data, 6 * HOUR_IN_SECONDS);
    return $data;
}

// Fires for every plugin whose "Update URI" host is github.com — we only act on ours.
add_filter('update_plugins_github.com', 'fvc_bridge_check_update', 10, 3);
function fvc_bridge_check_update($update, $plugin_data, $plugin_file) {
    if ( $plugin_file !== FVC_BRIDGE_BASENAME ) {
        return $update;
    }
    $manifest = fvc_bridge_get_manifest();
    if ( ! $manifest || empty($manifest['version']) || empty($manifest['package']) ) {
        return $update;
    }
    // Security pin: only ever install packages from your own repo's releases.
    if ( strpos($manifest['package'], FVC_BRIDGE_PKG_PREFIX) !== 0 ) {
        return $update;
    }
    if ( version_compare($manifest['version'], FVC_BRIDGE_VERSION, '<=') ) {
        return $update;
    }
    return array(
        'slug'    => FVC_BRIDGE_SLUG,
        'version' => $manifest['version'],
        'url'     => 'https://github.com/rubenjdelacruz1985-jpg/fvc-bridge',
        'package' => $manifest['package'],
    );
}

/* ============================================================
 *  Phase 1 — submissions store, capture, duplicate detection
 * ============================================================ */

define('FVC_BRIDGE_DB_VERSION', '1');

function fvc_bridge_table() { global $wpdb; return $wpdb->prefix . 'fvc_listing_requests'; }

function fvc_bridge_install_tables() {
    if ( get_option('fvc_bridge_db_version') === FVC_BRIDGE_DB_VERSION ) return;
    global $wpdb;
    $table = fvc_bridge_table();
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE $table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        type VARCHAR(20) NOT NULL DEFAULT 'add',
        clinic_name VARCHAR(255) NOT NULL,
        listing_url VARCHAR(255) NULL,
        contact_name VARCHAR(255) NULL,
        role VARCHAR(100) NULL,
        email VARCHAR(255) NULL,
        phone VARCHAR(100) NULL,
        website VARCHAR(255) NULL,
        address VARCHAR(255) NULL,
        services TEXT NULL,
        icbc VARCHAR(20) NULL,
        worksafe VARCHAR(20) NULL,
        billing VARCHAR(20) NULL,
        booking VARCHAR(20) NULL,
        notes TEXT NULL,
        marketing_consent TINYINT(1) NOT NULL DEFAULT 0,
        matched_post_id BIGINT UNSIGNED NULL,
        match_score INT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'new',
        created_at DATETIME NOT NULL,
        PRIMARY KEY  (id),
        KEY status (status),
        KEY type (type)
    ) $charset;";
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
    update_option('fvc_bridge_db_version', FVC_BRIDGE_DB_VERSION);
}
add_action('init', 'fvc_bridge_install_tables');

// -- normalisation --
function fvc_bridge_norm_name($s) {
    $s = strtolower((string) $s);
    $s = str_replace('&', ' and ', $s);
    $s = preg_replace('/[^a-z0-9]+/', ' ', $s);
    $s = preg_replace('/\b(the|clinic|clinics|centre|center|health|wellness|inc|ltd)\b/', ' ', $s);
    return trim(preg_replace('/\s+/', ' ', $s));
}
function fvc_bridge_norm_domain($u) {
    $u = strtolower((string) $u);
    $u = preg_replace('#^https?://#', '', $u);
    $u = preg_replace('#^www\.#', '', $u);
    $parts = preg_split('#[/?\#]#', $u);
    return trim($parts[0]);
}
function fvc_bridge_norm_phone($p) {
    $d = preg_replace('/\D/', '', (string) $p);
    return strlen($d) >= 10 ? substr($d, -10) : '';
}
function fvc_bridge_norm_street($s) {
    $s = strtolower((string) $s);
    $s = preg_replace('/[^a-z0-9]+/', ' ', $s);
    return trim(preg_replace('/\s+/', ' ', $s));
}

// Best match for a candidate against published listings (>=45 score, else null).
function fvc_bridge_find_match($cand) {
    global $wpdb;
    $rows = $wpdb->get_results(
        "SELECT p.ID AS post_id, p.post_title AS name, d.street, d.`l` AS phone, d.website
         FROM {$wpdb->prefix}posts p
         JOIN {$wpdb->prefix}geodir_gd_place_detail d ON d.post_id = p.ID
         WHERE p.post_type = 'gd_place' AND p.post_status = 'publish'", ARRAY_A);
    if ( ! $rows ) return null;

    $cn = fvc_bridge_norm_name($cand['name'] ?? '');
    $cd = fvc_bridge_norm_domain($cand['website'] ?? '');
    $cp = fvc_bridge_norm_phone($cand['phone'] ?? '');
    $cs = fvc_bridge_norm_street($cand['address'] ?? '');
    $best = null; $bestScore = 0;

    foreach ( $rows as $r ) {
        $score = 0;
        $rd = fvc_bridge_norm_domain($r['website']);
        $rp = fvc_bridge_norm_phone($r['phone']);
        $rn = fvc_bridge_norm_name($r['name']);
        $rs = fvc_bridge_norm_street($r['street']);
        if ( $cd && $rd && $cd === $rd ) $score = max($score, 98);
        if ( $cp && $rp && $cp === $rp ) $score = max($score, 92);
        $ns = 0;
        if ( $cn && $rn ) {
            if ( $cn === $rn ) $ns = 60;
            elseif ( strpos($rn, $cn) !== false || strpos($cn, $rn) !== false ) $ns = 42;
            else {
                $cw = array_values(array_filter(explode(' ', $cn), function ($w) { return strlen($w) > 2; }));
                $rw = explode(' ', $rn);
                $ov = 0;
                foreach ( $cw as $w ) { foreach ( $rw as $x ) { if ( strpos($x, $w) !== false ) { $ov++; break; } } }
                $ns = count($cw) ? round(($ov / count($cw)) * 35) : 0;
            }
        }
        $ss = 0;
        if ( $cs && $rs ) {
            $csn = implode(' ', array_slice(explode(' ', $cs), 0, 3));
            if ( $csn && strpos($rs, $csn) !== false ) $ss = 30;
        }
        $score = max($score, $ns + $ss);
        if ( $score > $bestScore ) { $bestScore = $score; $best = $r; }
    }
    if ( $best && $bestScore >= 45 ) {
        return array('score' => min(100, (int) $bestScore), 'post_id' => (int) $best['post_id'], 'name' => $best['name'], 'url' => get_permalink($best['post_id']));
    }
    return null;
}

function fvc_bridge_store_submission($type, $data) {
    global $wpdb;
    $wpdb->insert(fvc_bridge_table(), array(
        'type'              => ($type === 'claim' ? 'claim' : 'add'),
        'clinic_name'       => substr((string) ($data['clinic_name'] ?? ''), 0, 255),
        'listing_url'       => $data['listing_url'] ?? null,
        'contact_name'      => $data['contact_name'] ?? null,
        'role'              => $data['role'] ?? null,
        'email'             => $data['email'] ?? null,
        'phone'             => $data['phone'] ?? null,
        'website'           => $data['website'] ?? null,
        'address'           => $data['address'] ?? null,
        'services'          => $data['services'] ?? null,
        'icbc'              => $data['icbc'] ?? null,
        'worksafe'          => $data['worksafe'] ?? null,
        'billing'           => $data['billing'] ?? null,
        'booking'           => $data['booking'] ?? null,
        'notes'             => $data['notes'] ?? null,
        'marketing_consent' => ! empty($data['marketing_consent']) ? 1 : 0,
        'matched_post_id'   => ! empty($data['matched_post_id']) ? absint($data['matched_post_id']) : null,
        'match_score'       => isset($data['match_score']) ? (int) $data['match_score'] : null,
        'status'            => 'new',
        'created_at'        => current_time('mysql'),
    ));
    return (int) $wpdb->insert_id;
}

// Capture both existing forms (priority 1, does not exit — the real handler still runs).
add_action('wp_ajax_fvc_new_listing',        'fvc_bridge_capture', 1);
add_action('wp_ajax_nopriv_fvc_new_listing', 'fvc_bridge_capture', 1);
add_action('wp_ajax_fvc_claim',              'fvc_bridge_capture', 1);
add_action('wp_ajax_nopriv_fvc_claim',       'fvc_bridge_capture', 1);
function fvc_bridge_capture() {
    if ( ! isset($_POST['nonce']) || ! wp_verify_nonce($_POST['nonce'], 'fvc_claim_nonce') ) return;
    $type    = (strpos(current_action(), 'fvc_claim') !== false) ? 'claim' : 'add';
    $clinic  = sanitize_text_field($_POST['clinic_name'] ?? '');
    $email   = sanitize_email($_POST['email'] ?? '');
    $contact = sanitize_text_field($_POST['contact_name'] ?? '');
    if ( ! $clinic || ! $email || ! $contact ) return;

    $cand  = array(
        'name'    => $clinic,
        'website' => esc_url_raw($_POST['clinic_website'] ?? ''),
        'phone'   => sanitize_text_field($_POST['phone'] ?? ''),
        'address' => sanitize_text_field($_POST['clinic_address'] ?? ''),
    );
    $match = fvc_bridge_find_match($cand);

    fvc_bridge_store_submission($type, array(
        'clinic_name'       => $clinic,
        'listing_url'       => esc_url_raw($_POST['listing_url'] ?? ''),
        'website'           => $cand['website'],
        'address'           => $cand['address'],
        'contact_name'      => $contact,
        'role'              => sanitize_text_field($_POST['role'] ?? ''),
        'email'             => $email,
        'phone'             => $cand['phone'],
        'services'          => sanitize_text_field($_POST['services'] ?? ''),
        'icbc'              => sanitize_text_field($_POST['icbc'] ?? ''),
        'worksafe'          => sanitize_text_field($_POST['worksafe'] ?? ''),
        'billing'           => sanitize_text_field($_POST['billing'] ?? ''),
        'booking'           => sanitize_text_field($_POST['booking'] ?? ''),
        'notes'             => sanitize_textarea_field($_POST['notes'] ?? ''),
        'marketing_consent' => ! empty($_POST['marketing_consent']),
        'matched_post_id'   => $match ? $match['post_id'] : null,
        'match_score'       => $match ? $match['score'] : null,
    ));
}

// REST: public duplicate check for the front-end form.
function fvc_bridge_rest_check_dup($req) {
    $ip = fvc_bridge_ip();
    $k  = 'fvc_bridge_dup_rl_' . md5($ip);
    $c  = (int) get_transient($k);
    if ( $c > 30 ) return new WP_REST_Response(array('error' => 'rate_limited'), 429);
    set_transient($k, $c + 1, MINUTE_IN_SECONDS);

    $p = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $match = fvc_bridge_find_match(array(
        'name'    => $p['clinic_name'] ?? $p['name'] ?? '',
        'website' => $p['clinic_website'] ?? $p['website'] ?? '',
        'phone'   => $p['phone'] ?? '',
        'address' => $p['clinic_address'] ?? $p['address'] ?? '',
    ));
    if ( $match ) {
        return new WP_REST_Response(array(
            'match'   => true,
            'score'   => $match['score'],
            'listing' => array('name' => $match['name'], 'url' => $match['url'], 'post_id' => $match['post_id']),
        ), 200);
    }
    return new WP_REST_Response(array('match' => false), 200);
}

// REST: token-gated list of stored submissions for review tooling.
function fvc_bridge_rest_submissions($req) {
    global $wpdb;
    $status = sanitize_text_field($req->get_param('status') ?: 'new');
    $table  = fvc_bridge_table();
    $rows   = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM $table WHERE status = %s ORDER BY created_at DESC LIMIT 200", $status), ARRAY_A);
    return new WP_REST_Response(array('count' => count($rows), 'submissions' => $rows), 200);
}

/* ============================================================
 *  Settings screen — generate/revoke tokens (Settings > FVC Bridge)
 * ============================================================ */

add_action('admin_menu', function () {
    add_options_page('FVC Bridge', 'FVC Bridge', 'manage_options', 'fvc-bridge', 'fvc_bridge_settings_page');
});

function fvc_bridge_settings_page() {
    if ( ! current_user_can('manage_options') ) return;

    $new_token = '';

    if ( isset($_POST['fvc_bridge_action']) && check_admin_referer('fvc_bridge_settings') ) {
        $tokens = get_option('fvc_bridge_tokens', array());
        if ( ! is_array($tokens) ) $tokens = array();

        if ( $_POST['fvc_bridge_action'] === 'generate' ) {
            $new_token = bin2hex(random_bytes(24)); // 48-char token, shown once
            $tokens[]  = array(
                'hash'    => hash('sha256', $new_token),
                'label'   => sanitize_text_field($_POST['label'] ?? 'token'),
                'created' => current_time('mysql'),
            );
            update_option('fvc_bridge_tokens', $tokens, false);
            fvc_bridge_log('token-created', sanitize_text_field($_POST['label'] ?? 'token'));
        } elseif ( $_POST['fvc_bridge_action'] === 'revoke' ) {
            $idx = (int) ($_POST['idx'] ?? -1);
            if ( isset($tokens[$idx]) ) {
                fvc_bridge_log('token-revoked', $tokens[$idx]['label'] ?? '');
                unset($tokens[$idx]);
                update_option('fvc_bridge_tokens', array_values($tokens), false);
            }
        }
    }

    $tokens = get_option('fvc_bridge_tokens', array());
    if ( ! is_array($tokens) ) $tokens = array();
    echo '<div class="wrap"><h1>FVC Bridge</h1>';
    echo '<p>Plugin version: <strong>' . esc_html(FVC_BRIDGE_VERSION) . '</strong></p>';

    if ( $new_token ) {
        echo '<div class="notice notice-success"><p><strong>New token (copy it now — it will not be shown again):</strong><br>'
           . '<code style="font-size:14px">' . esc_html($new_token) . '</code></p></div>';
    }

    echo '<h2>Tokens</h2><table class="widefat"><thead><tr><th>Label</th><th>Created</th><th></th></tr></thead><tbody>';
    if ( ! $tokens ) {
        echo '<tr><td colspan="3">No tokens yet.</td></tr>';
    } else {
        foreach ( $tokens as $i => $t ) {
            echo '<tr><td>' . esc_html($t['label'] ?? '') . '</td><td>' . esc_html($t['created'] ?? '') . '</td><td>';
            echo '<form method="post" style="margin:0">';
            wp_nonce_field('fvc_bridge_settings');
            echo '<input type="hidden" name="fvc_bridge_action" value="revoke"><input type="hidden" name="idx" value="' . (int) $i . '">';
            echo '<button class="button button-small" type="submit">Revoke</button></form></td></tr>';
        }
    }
    echo '</tbody></table>';

    echo '<h2>Generate a token</h2><form method="post">';
    wp_nonce_field('fvc_bridge_settings');
    echo '<input type="hidden" name="fvc_bridge_action" value="generate">';
    echo '<input type="text" name="label" placeholder="e.g. claude-manager" class="regular-text"> ';
    echo '<button class="button button-primary" type="submit">Generate</button></form>';
    echo '</div>';
}
