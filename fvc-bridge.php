<?php
/**
 * Plugin Name: FVC Bridge
 * Description: Token-authenticated REST bridge + self-update channel for Find Vancouver Clinics.
 * Version: 1.0.0
 * Author: Ruben de la Cruz
 * Update URI: https://github.com/rubenjdelacruz1985-jpg/fvc-bridge
 */

if ( ! defined('ABSPATH') ) exit;

define('FVC_BRIDGE_VERSION',    '1.0.0');
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
