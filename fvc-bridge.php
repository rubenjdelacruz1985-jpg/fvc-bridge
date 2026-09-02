<?php
/**
 * Plugin Name: FVC Bridge
 * Description: Token-authenticated REST bridge + self-update channel for Find Vancouver Clinics.
 * Version: 1.2.0
 * Author: Ruben de la Cruz
 * Update URI: https://github.com/rubenjdelacruz1985-jpg/fvc-bridge
 */

if ( ! defined('ABSPATH') ) exit;

define('FVC_BRIDGE_VERSION',    '1.2.0');
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

/* ---- Form handlers owned by the bridge (disable WPCode #1071 & #1015) ---- */
// Unique function names so there's no fatal clash if a WPCode snippet lingers.

// Keep the forms' nonce available even after the WPCode snippets are disabled.
add_action('wp_footer', function () {
    echo '<script>window.fvcAjax = { url: "' . esc_url(admin_url('admin-ajax.php')) . '", nonce: "' . esc_js(wp_create_nonce('fvc_claim_nonce')) . '" };</script>';
});

function fvc_bridge_brevo_key() {
    return defined('FVC_BREVO_API_KEY') ? (string) FVC_BREVO_API_KEY : '';
}

function fvc_bridge_email_shell($preheader, $heading, $inner_html) {
    return '<div style="display:none;max-height:0;overflow:hidden;opacity:0;">' . esc_html($preheader) . '</div>'
    . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;font-family:Segoe UI,Helvetica,Arial,sans-serif;"><tr><td align="center">'
    . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#fff;border-radius:12px;overflow:hidden;">'
    . '<tr><td style="background:#09090B;padding:26px 32px;"><span style="color:#fff;font-size:20px;font-weight:700;">Find Vancouver Clinics</span><span style="color:#09BDB8;font-size:20px;font-weight:700;"> &#10003;</span></td></tr>'
    . '<tr><td style="height:4px;background:#09BDB8;font-size:0;line-height:0;">&nbsp;</td></tr>'
    . '<tr><td style="padding:34px 32px 8px;"><h1 style="margin:0 0 14px;font-size:23px;line-height:1.25;color:#09090B;">' . $heading . '</h1>' . $inner_html
    . '<p style="margin:14px 0 0;font-size:14px;color:#6b6b6e;">&mdash; The Find Vancouver Clinics team</p></td></tr>'
    . '<tr><td style="padding:22px 32px;background:#fafafa;border-top:1px solid #eee;"><p style="margin:0;font-size:12px;line-height:1.5;color:#9ca3af;">Find Vancouver Clinics &middot; Vancouver, BC<br>You received this because you contacted us at <a href="https://findvancouverclinics.com" style="color:#6b6b6e;">findvancouverclinics.com</a>.</p></td></tr>'
    . '</table></td></tr></table>';
}

function fvc_bridge_send_brevo($email, $contact_name, $attrs) {
    $key = fvc_bridge_brevo_key();
    if ( ! $key ) return;
    $name_parts = explode(' ', $contact_name, 2);
    wp_remote_post('https://api.brevo.com/v3/contacts', array(
        'headers' => array('accept' => 'application/json', 'content-type' => 'application/json', 'api-key' => $key),
        'body'    => json_encode(array(
            'email' => $email, 'listIds' => array(4), 'updateEnabled' => true,
            'attributes' => array_merge(array('FIRSTNAME' => $name_parts[0], 'LASTNAME' => isset($name_parts[1]) ? $name_parts[1] : ''), $attrs),
        )),
        'timeout' => 15,
    ));
}

function fvc_bridge_collect_post() {
    return array(
        'clinic_name' => sanitize_text_field($_POST['clinic_name'] ?? ''),
        'website'     => esc_url_raw($_POST['clinic_website'] ?? ''),
        'address'     => sanitize_text_field($_POST['clinic_address'] ?? ''),
        'listing_url' => esc_url_raw($_POST['listing_url'] ?? ''),
        'contact'     => sanitize_text_field($_POST['contact_name'] ?? ''),
        'role'        => sanitize_text_field($_POST['role'] ?? ''),
        'email'       => sanitize_email($_POST['email'] ?? ''),
        'phone'       => sanitize_text_field($_POST['phone'] ?? ''),
        'services'    => sanitize_text_field($_POST['services'] ?? 'Not specified'),
        'icbc'        => sanitize_text_field($_POST['icbc'] ?? 'Not answered'),
        'worksafe'    => sanitize_text_field($_POST['worksafe'] ?? 'Not answered'),
        'billing'     => sanitize_text_field($_POST['billing'] ?? 'Not answered'),
        'booking'     => sanitize_text_field($_POST['booking'] ?? 'Not answered'),
        'notes'       => sanitize_textarea_field($_POST['notes'] ?? ''),
        'consent'     => ! empty($_POST['marketing_consent']),
    );
}

add_action('wp_ajax_fvc_new_listing',        'fvc_bridge_new_listing_handler');
add_action('wp_ajax_nopriv_fvc_new_listing', 'fvc_bridge_new_listing_handler');
function fvc_bridge_new_listing_handler() {
    if ( ! isset($_POST['nonce']) || ! wp_verify_nonce($_POST['nonce'], 'fvc_claim_nonce') ) { wp_send_json_error('Invalid request'); }
    $d = fvc_bridge_collect_post();
    if ( ! $d['clinic_name'] || ! $d['email'] || ! $d['contact'] ) { wp_send_json_error('Missing required fields'); }

    $match = fvc_bridge_find_match(array('name' => $d['clinic_name'], 'website' => $d['website'], 'phone' => $d['phone'], 'address' => $d['address']));
    fvc_bridge_store_submission('add', array(
        'clinic_name' => $d['clinic_name'], 'website' => $d['website'], 'address' => $d['address'],
        'contact_name' => $d['contact'], 'role' => $d['role'], 'email' => $d['email'], 'phone' => $d['phone'],
        'services' => $d['services'], 'icbc' => $d['icbc'], 'worksafe' => $d['worksafe'], 'billing' => $d['billing'], 'booking' => $d['booking'],
        'notes' => $d['notes'], 'marketing_consent' => $d['consent'],
        'matched_post_id' => $match ? $match['post_id'] : null, 'match_score' => $match ? $match['score'] : null,
    ));

    $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>', 'Reply-To: ' . $d['contact'] . ' <' . $d['email'] . '>');
    $admin = '<h2>New Listing Request</h2><ul>'
        . '<li>Clinic: ' . esc_html($d['clinic_name']) . '</li>'
        . '<li>Website: ' . esc_html($d['website']) . '</li>'
        . '<li>Address: ' . esc_html($d['address']) . '</li>'
        . '<li>Contact: ' . esc_html($d['contact']) . ' (' . esc_html($d['role']) . ')</li>'
        . '<li>Email: ' . esc_html($d['email']) . ' | Phone: ' . esc_html($d['phone']) . '</li>'
        . '<li>Services: ' . esc_html($d['services']) . '</li>'
        . '<li>ICBC/WSBC: ' . esc_html($d['icbc']) . ' / ' . esc_html($d['worksafe']) . ' | Billing/Booking: ' . esc_html($d['billing']) . ' / ' . esc_html($d['booking']) . '</li>'
        . '<li>Marketing consent: ' . ($d['consent'] ? 'Yes' : 'No') . '</li>'
        . ($match ? '<li><strong>Possible duplicate:</strong> ' . esc_html($match['name']) . ' (score ' . $match['score'] . ') ' . esc_url($match['url']) . '</li>' : '')
        . ($d['notes'] ? '<li>Notes: ' . esc_html($d['notes']) . '</li>' : '') . '</ul>';
    $sent = wp_mail('claim@findvancouverclinics.com', 'New Listing Request: ' . $d['clinic_name'], $admin, $headers);

    $confirm = fvc_bridge_email_shell(
        'Your clinic is in our review queue - live within 48 hours.',
        'Thanks, ' . esc_html($d['contact']) . ' - we&#39;ve got it.',
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">We received your submission for <strong>' . esc_html($d['clinic_name']) . '</strong>. It&#39;s now in our review queue.</p>'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px;">'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">1.</span>&nbsp; We review your details for accuracy.</td></tr>'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">2.</span>&nbsp; Your clinic goes live - usually within <strong>48 hours</strong>.</td></tr>'
        . '<tr><td style="padding:10px 0;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">3.</span>&nbsp; We email you the link the moment it&#39;s published.</td></tr></table>'
        . '<table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:8px;background:#09BDB8;"><a href="https://findvancouverclinics.com/places/" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#fff;text-decoration:none;">Browse the directory &rarr;</a></td></tr></table>'
    );
    wp_mail($d['email'], 'We received your listing request - Find Vancouver Clinics', $confirm, $headers);

    if ( $d['consent'] ) {
        fvc_bridge_send_brevo($d['email'], $d['contact'], array('CLINIC_NAME' => $d['clinic_name'], 'ROLE' => $d['role'], 'CLAIM_STATUS' => 'new_listing', 'SERVICES' => $d['services'], 'ICBC_APPROVED' => $d['icbc'], 'WORKSAFE_APPROVED' => $d['worksafe'], 'DIRECT_BILLING' => $d['billing'], 'ONLINE_BOOKING' => $d['booking']));
    }
    $sent ? wp_send_json_success('Listing request submitted') : wp_send_json_error('Mail failed');
}

add_action('wp_ajax_fvc_claim',        'fvc_bridge_claim_handler');
add_action('wp_ajax_nopriv_fvc_claim', 'fvc_bridge_claim_handler');
function fvc_bridge_claim_handler() {
    if ( ! isset($_POST['nonce']) || ! wp_verify_nonce($_POST['nonce'], 'fvc_claim_nonce') ) { wp_send_json_error('Invalid request'); }
    $d = fvc_bridge_collect_post();
    if ( ! $d['clinic_name'] || ! $d['email'] || ! $d['contact'] ) { wp_send_json_error('Missing required fields'); }

    $match = fvc_bridge_find_match(array('name' => $d['clinic_name']));
    fvc_bridge_store_submission('claim', array(
        'clinic_name' => $d['clinic_name'], 'listing_url' => $d['listing_url'],
        'contact_name' => $d['contact'], 'role' => $d['role'], 'email' => $d['email'], 'phone' => $d['phone'],
        'services' => $d['services'], 'icbc' => $d['icbc'], 'worksafe' => $d['worksafe'], 'billing' => $d['billing'], 'booking' => $d['booking'],
        'notes' => $d['notes'], 'marketing_consent' => $d['consent'],
        'matched_post_id' => $match ? $match['post_id'] : null, 'match_score' => $match ? $match['score'] : null,
    ));

    $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>', 'Reply-To: ' . $d['contact'] . ' <' . $d['email'] . '>');
    $admin_link = $match ? '<li>Edit: ' . esc_url(admin_url('post.php?post=' . $match['post_id'] . '&action=edit')) . '</li>' : '';
    $admin = '<h2>New Claim Request</h2><ul>'
        . '<li>Clinic: ' . esc_html($d['clinic_name']) . '</li>'
        . ($d['listing_url'] ? '<li>Listing: ' . esc_html($d['listing_url']) . '</li>' : '')
        . $admin_link
        . '<li>Contact: ' . esc_html($d['contact']) . ' (' . esc_html($d['role']) . ')</li>'
        . '<li>Email: ' . esc_html($d['email']) . ' | Phone: ' . esc_html($d['phone']) . '</li>'
        . '<li>Marketing consent: ' . ($d['consent'] ? 'Yes' : 'No') . '</li>'
        . ($d['notes'] ? '<li>Notes: ' . esc_html($d['notes']) . '</li>' : '') . '</ul>';
    $sent = wp_mail('claim@findvancouverclinics.com', 'New Claim Request: ' . $d['clinic_name'], $admin, $headers);

    $confirm = fvc_bridge_email_shell(
        'Claim request received',
        'Thanks, ' . esc_html($d['contact']) . ' - we&#39;ve got it.',
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">We received your request to claim <strong>' . esc_html($d['clinic_name']) . '</strong>. Here&#39;s what happens next:</p>'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px;">'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">1.</span>&nbsp; We verify you&#39;re connected to the clinic.</td></tr>'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">2.</span>&nbsp; We reach out within <strong>1-2 business days</strong>.</td></tr>'
        . '<tr><td style="padding:10px 0;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">3.</span>&nbsp; Once confirmed, you get access to manage your listing.</td></tr></table>'
    );
    wp_mail($d['email'], 'We received your claim request - Find Vancouver Clinics', $confirm, $headers);

    if ( $d['consent'] ) {
        fvc_bridge_send_brevo($d['email'], $d['contact'], array('CLINIC_NAME' => $d['clinic_name'], 'ROLE' => $d['role'], 'CLAIM_STATUS' => 'pending', 'SERVICES' => $d['services'], 'ICBC_APPROVED' => $d['icbc'], 'WORKSAFE_APPROVED' => $d['worksafe'], 'DIRECT_BILLING' => $d['billing'], 'ONLINE_BOOKING' => $d['booking']));
    }
    $sent ? wp_send_json_success('Claim submitted') : wp_send_json_error('Mail failed');
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
