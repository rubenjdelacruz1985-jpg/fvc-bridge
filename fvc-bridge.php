<?php
/**
 * Plugin Name: FVC Bridge
 * Description: Token-authenticated REST bridge + self-update channel for Find Vancouver Clinics.
 * Version: 1.16.79
 * Author: Ruben de la Cruz
 * Update URI: https://github.com/rubenjdelacruz1985-jpg/fvc-bridge
 */

if ( ! defined('ABSPATH') ) exit;

define('FVC_BRIDGE_VERSION',    '1.16.79');
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
    // Internal reuse from the wp-admin page (logged-in admin only, no token needed).
    if ( ! empty($GLOBALS['fvc_bridge_internal']) && current_user_can('manage_options') ) {
        return true;
    }
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

// Boolean token check (no rate-limit side effects) — for endpoints that accept EITHER a WP login or a token.
function fvc_bridge_has_valid_token() {
    if ( ! empty($GLOBALS['fvc_bridge_internal']) && current_user_can('manage_options') ) return true;
    $token = fvc_bridge_bearer_token();
    if ( ! $token ) return false;
    $hash = hash('sha256', $token);
    foreach ( get_option('fvc_bridge_tokens', array()) as $t ) {
        if ( ! empty($t['hash']) && hash_equals($t['hash'], $hash) ) return true;
    }
    return false;
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
    // Token-gated: inspect the anatomy of an existing published listing.
    register_rest_route('fvc-bridge/v1', '/inspect-listing', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_inspect',
    ));
    // Token-gated: publish an already-stored, approved submission BY ID.
    register_rest_route('fvc-bridge/v1', '/create-listing', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_create_listing',
    ));
    // Token-gated: read a page's Elementor data (to inspect/edit page content natively).
    register_rest_route('fvc-bridge/v1', '/page-elementor', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_page_elementor_get',
    ));
    // Token-gated: write a page's Elementor data back (native page-content editing).
    register_rest_route('fvc-bridge/v1', '/page-elementor-save', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_page_elementor_save',
    ));
    // Token-gated: send the "your listing is now live" email for a published listing.
    register_rest_route('fvc-bridge/v1', '/notify-live', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_notify_live',
    ));
    // Token-gated: approve a stored CLAIM by ID — grants the owner edit access.
    register_rest_route('fvc-bridge/v1', '/approve-claim', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_approve_claim',
    ));
    // Token-gated: publish a blog post (SEO content).
    register_rest_route('fvc-bridge/v1', '/publish-post', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_publish_post',
    ));
    // Token-gated: set a post's featured image from a base64-encoded image.
    register_rest_route('fvc-bridge/v1', '/set-featured-image', array(
        'methods'             => 'POST',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_set_featured_image',
    ));
    // Token-gated: list recent media-library images (to reuse existing photos).
    register_rest_route('fvc-bridge/v1', '/media', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_media',
    ));
    // Token-gated: Google ratings per listing (post_id => {rating, count}) from the detail table.
    register_rest_route('fvc-bridge/v1', '/ratings', array(
        'methods'             => 'GET',
        'permission_callback' => 'fvc_bridge_require_token',
        'callback'            => 'fvc_bridge_rest_ratings',
    ));
    // Clinic Site Builder: a logged-in owner (or admin/token tooling) publishes their clinic's site.
    register_rest_route('fvc-bridge/v1', '/clinic-publish', array(
        'methods'             => 'POST',
        'permission_callback' => function () { return is_user_logged_in() || fvc_bridge_has_valid_token(); },
        'callback'            => 'fvc_bridge_rest_clinic_publish',
    ));
    // Who am I + which listings I own (for the builder's owner-gating). Logged-in only.
    register_rest_route('fvc-bridge/v1', '/clinic-me', array(
        'methods'             => 'GET',
        'permission_callback' => function () { return is_user_logged_in(); },
        'callback'            => 'fvc_bridge_rest_clinic_me',
    ));
    // Take a clinic's site offline (set its page to draft) — owner of the listing, admin, or token.
    register_rest_route('fvc-bridge/v1', '/clinic-unpublish', array(
        'methods'             => 'POST',
        'permission_callback' => function () { return is_user_logged_in() || fvc_bridge_has_valid_token(); },
        'callback'            => 'fvc_bridge_rest_clinic_unpublish',
    ));
    // ---- Booking v1 (native) ----
    register_rest_route('fvc-bridge/v1', '/booking-config', array('methods'=>'GET','permission_callback'=>'__return_true','callback'=>'fvc_bridge_rest_booking_config'));
    register_rest_route('fvc-bridge/v1', '/booking-config-save', array('methods'=>'POST','permission_callback'=>function(){return is_user_logged_in()||fvc_bridge_has_valid_token();},'callback'=>'fvc_bridge_rest_booking_config_save'));
    register_rest_route('fvc-bridge/v1', '/booking-slots', array('methods'=>'GET','permission_callback'=>'__return_true','callback'=>'fvc_bridge_rest_booking_slots'));
    register_rest_route('fvc-bridge/v1', '/booking-create', array('methods'=>'POST','permission_callback'=>'fvc_bridge_require_token_or_public','callback'=>'fvc_bridge_rest_booking_create'));
    register_rest_route('fvc-bridge/v1', '/booking-list', array('methods'=>'GET','permission_callback'=>function(){return is_user_logged_in()||fvc_bridge_has_valid_token();},'callback'=>'fvc_bridge_rest_booking_list'));
    register_rest_route('fvc-bridge/v1', '/booking-status', array('methods'=>'POST','permission_callback'=>'__return_true','callback'=>'fvc_bridge_rest_booking_status'));
    register_rest_route('fvc-bridge/v1', '/booking-ics', array('methods'=>'GET','permission_callback'=>'__return_true','callback'=>'fvc_bridge_rest_booking_ics'));
    register_rest_route('fvc-bridge/v1', '/booking-feed', array('methods'=>'GET','permission_callback'=>'__return_true','callback'=>'fvc_bridge_rest_booking_feed'));
    register_rest_route('fvc-bridge/v1', '/clinic-generate', array('methods'=>'POST','permission_callback'=>function(){return is_user_logged_in()||fvc_bridge_has_valid_token();},'callback'=>'fvc_bridge_rest_clinic_generate'));
    // Public read: a clinic's listing data, formatted to seed the site builder.
    register_rest_route('fvc-bridge/v1', '/clinic-data', array(
        'methods'             => 'GET',
        'permission_callback' => '__return_true',
        'callback'            => 'fvc_bridge_rest_clinic_data',
    ));
    // Token-gated: upload a base64 image to the media library, return its URL (builds the photo library).
    register_rest_route('fvc-bridge/v1', '/upload-image', array(
        'methods'             => 'POST',
        'permission_callback' => function () { return ( is_user_logged_in() && current_user_can('upload_files') ) || fvc_bridge_has_valid_token(); },
        'callback'            => 'fvc_bridge_rest_upload_image',
    ));
});

function fvc_bridge_rest_upload_image($req) {
    require_once ABSPATH . 'wp-admin/includes/image.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';
    $p = $req->get_json_params();
    $b64 = $p['image_base64'] ?? '';
    $fn = sanitize_file_name($p['filename'] ?? ('img-' . time() . '.jpg'));
    if ( ! $b64 ) return new WP_REST_Response(array('ok' => false, 'error' => 'no image'), 400);
    $up = wp_upload_bits($fn, null, base64_decode($b64));
    if ( ! empty($up['error']) ) return new WP_REST_Response(array('ok' => false, 'error' => $up['error']), 500);
    $ft = wp_check_filetype($up['file']);
    $aid = wp_insert_attachment(array('post_mime_type' => $ft['type'], 'post_title' => preg_replace('/\.[^.]+$/', '', $fn), 'post_status' => 'inherit'), $up['file']);
    wp_update_attachment_metadata($aid, wp_generate_attachment_metadata($aid, $up['file']));
    if ( ! empty($p['alt']) ) update_post_meta($aid, '_wp_attachment_image_alt', sanitize_text_field($p['alt']));
    return new WP_REST_Response(array('ok' => true, 'id' => $aid, 'url' => wp_get_attachment_url($aid)), 200);
}

// Return one clinic's public listing data (name, contact, rating, categories, flags) for the builder.
function fvc_bridge_rest_clinic_data($req) {
    global $wpdb;
    $id = (int) $req->get_param('listing');
    if ( ! $id ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing id required'), 400);
    $post = get_post($id);
    if ( ! $post || $post->post_type !== 'gd_place' ) return new WP_REST_Response(array('ok' => false, 'error' => 'not found'), 404);
    $d = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}geodir_gd_place_detail WHERE post_id = %d", $id), ARRAY_A);
    $d = $d ?: array();
    $yes = function ($v) { return $v === '1' || $v === 1 || $v === 'Yes'; };
    $cats = wp_get_post_terms($id, 'gd_placecategory', array('fields' => 'names'));
    return new WP_REST_Response(array(
        'ok'            => true,
        'listingId'     => $id,
        'name'          => html_entity_decode($post->post_title, ENT_QUOTES),
        'neighbourhood' => $d['neighbourhood'] ?? '',
        'city'          => $d['city'] ?? 'Vancouver',
        'address'       => trim($d['street'] ?? ''),
        'phone'         => $d['l'] ?? '',
        'hours'         => $d['business_hours'] ?? '',
        'rating'        => isset($d['google_rating']) ? (float) $d['google_rating'] : 0,
        'reviews'       => isset($d['google_review_count']) ? (int) $d['google_review_count'] : 0,
        'categories'    => array_values((array) $cats),
        'icbc'          => $yes($d['icbc_approved'] ?? ''),
        'directBilling' => $yes($d['direct_billing'] ?? ''),
        'onlineBooking' => $yes($d['online_booking_available'] ?? ''),
        'website'       => $d['website'] ?? '',
        'listingUrl'    => get_permalink($id),
        'sitePostId'    => (function () use ($id) { $s = (int) get_post_meta($id, '_fvc_site_page', true); return ($s && get_post($s)) ? $s : 0; })(),
        'placeId'       => $d['google_place_id'] ?? '',
        'writeReviewUrl'=> ! empty($d['google_place_id']) ? ('https://search.google.com/local/writereview?placeid=' . rawurlencode($d['google_place_id'])) : '',
    ), 200);
}

// Current user + the listings they own (post_author set on claim approval) — powers builder gating.
function fvc_bridge_rest_clinic_me($req) {
    nocache_headers(); // per-user data — never shared-cache
    $uid = get_current_user_id();
    if ( ! $uid ) return new WP_REST_Response(array('ok' => false, 'error' => 'not logged in'), 401);
    $posts = get_posts(array('post_type' => 'gd_place', 'author' => $uid, 'numberposts' => 20,
        'post_status' => array('publish', 'draft', 'pending')));
    $listings = array();
    foreach ( $posts as $po ) {
        $site = (int) get_post_meta($po->ID, '_fvc_site_page', true);
        $listings[] = array(
            'listingId' => $po->ID,
            'name'      => html_entity_decode($po->post_title, ENT_QUOTES),
            'siteUrl'   => ($site && get_post($site)) ? get_permalink($site) : '',
        );
    }
    $u = wp_get_current_user();
    return new WP_REST_Response(array('ok' => true, 'userId' => $uid, 'displayName' => $u->display_name,
        'isAdmin' => current_user_can('manage_options'), 'listings' => $listings), 200);
}

// Take a clinic's site offline (draft) — same ownership rules as clinic-publish.
function fvc_bridge_rest_clinic_unpublish($req) {
    $p = $req->get_json_params();
    $listing_id = (int) ($p['listing_id'] ?? $p['listingId'] ?? 0);
    if ( ! $listing_id ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing id required'), 400);
    $listing = get_post($listing_id);
    if ( ! $listing || $listing->post_type !== 'gd_place' ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing not found'), 404);
    $is_token = fvc_bridge_has_valid_token();
    $uid = get_current_user_id();
    $owns = $is_token || current_user_can('manage_options') || ( $uid && (int) $listing->post_author === $uid );
    if ( ! $owns ) return new WP_REST_Response(array('ok' => false, 'error' => 'you do not own this listing'), 403);
    $site_id = (int) get_post_meta($listing_id, '_fvc_site_page', true);
    if ( ! $site_id || ! get_post($site_id) ) return new WP_REST_Response(array('ok' => true, 'note' => 'no site to unpublish'), 200);
    wp_update_post(array('ID' => $site_id, 'post_status' => 'draft'));
    fvc_bridge_log('clinic-unpublish', "listing=$listing_id site=$site_id user=$uid token=" . ($is_token ? '1' : '0'));
    return new WP_REST_Response(array('ok' => true, 'post_id' => $site_id, 'status' => 'draft'), 200);
}

// Publish a clinic's white-label site. Two modes:
//  (a) listing_id  — the owner (post_author of the gd_place) OR admin/token creates/updates a
//      DEDICATED canvas page for that clinic (linked via _fvc_site_page / _fvc_site_listing).
//  (b) post_id     — legacy: update a specific page the caller can already edit.
function fvc_bridge_rest_clinic_publish($req) {
    $p = $req->get_json_params();
    $content = (string) ($p['content'] ?? '');
    if ( strlen($content) < 50 ) return new WP_REST_Response(array('ok' => false, 'error' => 'empty content'), 400);

    $is_token   = fvc_bridge_has_valid_token();
    $user_id    = get_current_user_id();
    $listing_id = (int) ($p['listing_id'] ?? $p['listingId'] ?? 0);

    if ( $listing_id ) {
        $listing = get_post($listing_id);
        if ( ! $listing || $listing->post_type !== 'gd_place' ) {
            return new WP_REST_Response(array('ok' => false, 'error' => 'listing not found'), 404);
        }
        $owns = $is_token || current_user_can('manage_options')
             || ( $user_id && (int) $listing->post_author === $user_id );
        if ( ! $owns ) return new WP_REST_Response(array('ok' => false, 'error' => 'you do not own this listing'), 403);

        $site_id = (int) get_post_meta($listing_id, '_fvc_site_page', true);
        if ( $site_id && ! get_post($site_id) ) $site_id = 0;
        $title  = html_entity_decode($listing->post_title, ENT_QUOTES);
        $author = ( $user_id && ! $is_token ) ? $user_id : (int) $listing->post_author;
        if ( ! $author ) $author = 1;

        kses_remove_filters();
        if ( $site_id ) {
            $r = wp_update_post(array('ID' => $site_id, 'post_content' => wp_slash($content), 'post_title' => $title), true);
        } else {
            $slug = ! empty($p['slug']) ? sanitize_title($p['slug']) : sanitize_title($title);
            $r = wp_insert_post(array(
                'post_type'    => 'page', 'post_status' => 'publish', 'post_title' => $title,
                'post_name'    => $slug, 'post_content' => wp_slash($content), 'post_author' => $author,
            ), true);
        }
        kses_init_filters();
        if ( is_wp_error($r) ) return new WP_REST_Response(array('ok' => false, 'error' => $r->get_error_message()), 500);
        if ( ! $site_id ) $site_id = (int) $r;

        update_post_meta($site_id, '_fvc_raw_html', 1);
        update_post_meta($site_id, '_wp_page_template', 'elementor_canvas'); // white-label standalone
        update_post_meta($site_id, '_fvc_site_listing', $listing_id);
        if ( ! empty($p['schema_jsonld']) ) update_post_meta($site_id, '_fvc_schema_b64', base64_encode((string) $p['schema_jsonld']));
        update_post_meta($listing_id, '_fvc_site_page', $site_id);

        if ( function_exists('fvc_bridge_indexnow_ping') ) fvc_bridge_indexnow_ping(get_permalink($site_id));
        fvc_bridge_log('clinic-publish', "listing=$listing_id site=$site_id user=$user_id token=" . ($is_token ? '1' : '0'));
        return new WP_REST_Response(array('ok' => true, 'post_id' => $site_id, 'view' => get_permalink($site_id)), 200);
    }

    // Legacy post_id mode.
    $post_id = (int) ($p['post_id'] ?? 0);
    if ( ! $post_id || ! ( $is_token || current_user_can('edit_post', $post_id) ) ) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'not allowed to edit this page'), 403);
    }
    update_post_meta($post_id, '_fvc_raw_html', 1);
    kses_remove_filters();
    $r = wp_update_post(array('ID' => $post_id, 'post_content' => wp_slash($content)), true);
    kses_init_filters();
    if ( is_wp_error($r) ) return new WP_REST_Response(array('ok' => false, 'error' => $r->get_error_message()), 500);
    if ( function_exists('fvc_bridge_indexnow_ping') ) fvc_bridge_indexnow_ping(get_permalink($post_id));
    return new WP_REST_Response(array('ok' => true, 'post_id' => $post_id, 'view' => get_permalink($post_id)), 200);
}

// REST: Google ratings map from the GeoDirectory detail table (google_rating/google_review_count).
function fvc_bridge_rest_ratings($req) {
    global $wpdb;
    $rows = $wpdb->get_results(
        "SELECT post_id, google_rating, google_review_count
         FROM {$wpdb->prefix}geodir_gd_place_detail
         WHERE google_rating IS NOT NULL AND google_rating > 0", ARRAY_A);
    $out = array();
    foreach ((array) $rows as $r) {
        $out[(int) $r['post_id']] = array(
            'rating' => round((float) $r['google_rating'], 1),
            'count'  => (int) $r['google_review_count'],
        );
    }
    return new WP_REST_Response(array('ok' => true, 'count' => count($out), 'ratings' => $out), 200);
}

// Emit per-post custom JSON-LD (stored by publish-post) into <head>.
add_action('wp_head', 'fvc_bridge_output_schema', 20);
function fvc_bridge_output_schema() {
    if ( ! is_singular() ) return;
    $b64 = get_post_meta(get_queried_object_id(), '_fvc_schema_b64', true);
    if ( ! $b64 ) return;
    $json = base64_decode($b64);
    if ( $json && json_decode($json) !== null ) {
        echo "\n<script type=\"application/ld+json\">" . $json . "</script>\n";
    }
}

// For raw_html posts, skip wpautop/wptexturize so our authored markup renders exactly as written.
add_filter('the_content', 'fvc_bridge_raw_content', 9);
function fvc_bridge_raw_content($content) {
    if ( is_singular() && in_the_loop() && is_main_query() && get_post_meta(get_the_ID(), '_fvc_raw_html', true) ) {
        remove_filter('the_content', 'wpautop');
        remove_filter('the_content', 'wptexturize');
    }
    return $content;
}

// Dark-theme the AI Clinic Finder form + results (colour-only override; no HTML/JS touched).
add_action('wp_head', 'fvc_bridge_finder_css', 30);
function fvc_bridge_finder_css() {
    if ( ! is_page('vancouver-clinic-finder') ) return;
    echo <<<'CSS'
<style id="fvc-finder-dark">
body .fvc-cf-widget-section.fvc-cf-widget-section{background:radial-gradient(1000px 480px at 12% -10%,rgba(9,189,184,.13),transparent 58%),#09090B !important;}
.fvc-cf-widget-section .fvc-cf-form-panel{background:transparent !important;border:0 !important;box-shadow:none !important;}
.fvc-cf-widget-section .fvc-cf-form-title{color:#fff !important;}
.fvc-cf-widget-section .fvc-cf-form-sub{color:rgba(255,255,255,.55) !important;}
.fvc-cf-widget-section .fvc-cf-dd-label,.fvc-cf-widget-section .fvc-cf-freetext-label,.fvc-cf-widget-section .fvc-cf-pref-label{color:#fff !important;}
.fvc-cf-widget-section .fvc-cf-freetext-opt{color:rgba(255,255,255,.4) !important;}
.fvc-cf-widget-section .fvc-cf-dd-trigger{background:transparent !important;border:0 !important;}
.fvc-cf-widget-section .fvc-cf-dd-value{color:rgba(255,255,255,.9) !important;}
.fvc-cf-widget-section .fvc-cf-dd-arrow{color:rgba(255,255,255,.5) !important;}
.fvc-cf-widget-section .fvc-cf-dd-options{background:#15171a !important;border:1px solid rgba(255,255,255,.12) !important;}
.fvc-cf-widget-section .fvc-cf-dd-option{color:rgba(255,255,255,.85) !important;}
.fvc-cf-widget-section .fvc-cf-freetext-input{background:transparent !important;border:0 !important;color:#fff !important;}
.fvc-cf-widget-section .fvc-cf-freetext-input::placeholder{color:rgba(255,255,255,.38) !important;}
.fvc-cf-widget-section .fvc-cf-care-row,.fvc-cf-widget-section .fvc-cf-freetext-row,.fvc-cf-widget-section .fvc-cf-pref-row{border-color:rgba(255,255,255,.1) !important;}
.fvc-cf-widget-section .fvc-cf-chip{background:transparent !important;border:1px solid rgba(255,255,255,.2) !important;color:rgba(255,255,255,.85) !important;}
.fvc-cf-widget-section .fvc-cf-submit{background:#09BDB8 !important;color:#fff !important;border:0 !important;}
.fvc-cf-widget-section .fvc-cf-submit.fvc-cf-disabled{background:rgba(255,255,255,.1) !important;color:rgba(255,255,255,.38) !important;opacity:1 !important;}
.fvc-cf-widget-section .fvc-cf-results-empty-label,.fvc-cf-widget-section .fvc-cf-results-intro,.fvc-cf-widget-section .fvc-cf-match-count,.fvc-cf-widget-section .fvc-cf-summary-label{color:rgba(255,255,255,.6) !important;}
.fvc-cf-widget-section .fvc-iw-clinic-card{background:#141619 !important;border:1px solid rgba(255,255,255,.08) !important;border-radius:12px !important;padding:18px 20px !important;margin-bottom:14px !important;}
.fvc-cf-widget-section .fvc-iw-clinic-name{color:#fff !important;}
.fvc-cf-widget-section .fvc-iw-clinic-name:hover{color:#2fd4cf !important;}
.fvc-cf-widget-section .fvc-iw-clinic-btn{color:#2fd4cf !important;}
.fvc-cf-widget-section .fvc-iw-clinic-blurb{color:rgba(255,255,255,.62) !important;}
.fvc-cf-widget-section .fvc-iw-badge{color:rgba(255,255,255,.7) !important;border:1px solid rgba(255,255,255,.18) !important;margin:0 6px 4px 0 !important;}
.fvc-cf-widget-section .fvc-iw-rating{color:#f5b60a !important;}
.fvc-cf-widget-section .fvc-iw-rating-count{color:rgba(255,255,255,.5) !important;}
</style>
<script>(function(){
  function inFinder(el){return el && el.closest && el.closest('.fvc-cf-widget-section');}
  // (1) Focusing a finder field triggers the browser's native focus-scroll (~430px jump).
  //     Force preventScroll on programmatic focus of finder fields; pin the scroll on
  //     pointer-down to also cover native click-focus.
  try{
    var _focus = HTMLElement.prototype.focus;
    HTMLElement.prototype.focus = function(opts){
      try{ if(this && this.closest && this.closest('.fvc-cf-widget-section')){ var o={preventScroll:true}; for(var k in (opts||{})) o[k]=opts[k]; o.preventScroll=true; return _focus.call(this,o); } }catch(_e){}
      return _focus.apply(this, arguments);
    };
  }catch(_e){}
  function pinScroll(){
    var y = window.pageYOffset, done = false;
    var iv = setInterval(function(){
      if(done) return;
      if(Math.abs(window.pageYOffset - y) > 80){ window.scrollTo(0, y); done = true; clearInterval(iv); }
    }, 20);
    setTimeout(function(){ done = true; clearInterval(iv); }, 600);
  }
  // Desktop: on mouse-down of a finder input, stop the native focus-scroll and refocus without it.
  document.addEventListener('mousedown', function(e){
    var t = e.target;
    if(!inFinder(t)) return;
    if(t.matches && t.matches('input,textarea')){ e.preventDefault(); try{ t.focus({preventScroll:true}); }catch(_e){ t.focus(); } }
    else { pinScroll(); }
  }, true);
  // Touch (mobile): can't preventDefault focus without breaking it — pin the scroll instead.
  document.addEventListener('touchstart', function(e){ if(inFinder(e.target)) pinScroll(); }, {capture:true, passive:true});
  // (2) After "Find my clinic", bring the results into view (they were rendering far below the form).
  document.addEventListener('click', function(e){
    var btn = e.target.closest && e.target.closest('.fvc-cf-submit');
    if(!btn) return;
    var tries = 0;
    var iv = setInterval(function(){
      tries++;
      var card = document.querySelector('.fvc-cf-widget-section .fvc-iw-clinic-card');
      if(card){
        clearInterval(iv);
        var top = card.getBoundingClientRect().top + window.pageYOffset - 96;
        if(top < window.pageYOffset - 40 || top > window.pageYOffset + 40) window.scrollTo({top: top, behavior: 'smooth'});
      } else if(tries > 25){ clearInterval(iv); }
    }, 200);
  }, true);
})();</script>
CSS;
}

// Read a page's Elementor data by slug — lets the bridge inspect/edit native page content.
function fvc_bridge_rest_page_elementor_get($req) {
    $slug = sanitize_title($req->get_param('slug'));
    $p = $slug ? get_page_by_path($slug, OBJECT, 'page') : null;
    if (!$p) return new WP_REST_Response(array('ok'=>false,'error'=>'page not found'), 404);
    $data = get_post_meta($p->ID, '_elementor_data', true);
    return new WP_REST_Response(array(
        'ok'        => true,
        'post_id'   => $p->ID,
        'edit_mode' => get_post_meta($p->ID, '_elementor_edit_mode', true),
        'length'    => is_string($data) ? strlen($data) : 0,
        'data'      => $data,
    ), 200);
}

// Write a page's Elementor data back. _elementor_data is stored SLASHED (Elementor convention);
// update_metadata unslashes, so pass wp_slash($json). Then bust Elementor's cached CSS.
function fvc_bridge_rest_page_elementor_save($req) {
    $slug = sanitize_title($req->get_param('slug'));
    $p = $slug ? get_page_by_path($slug, OBJECT, 'page') : null;
    if (!$p) return new WP_REST_Response(array('ok'=>false,'error'=>'page not found'), 404);
    // Data is sent base64-encoded so REST/WP slash handling can't mangle the JSON in transit.
    $b64 = $req->get_param('data_b64');
    if (!is_string($b64) || $b64 === '') return new WP_REST_Response(array('ok'=>false,'error'=>'no data_b64'), 400);
    $data = base64_decode($b64, true);
    if ($data === false || $data === '') return new WP_REST_Response(array('ok'=>false,'error'=>'bad base64'), 400);
    $decoded = json_decode($data, true);
    if (!is_array($decoded)) return new WP_REST_Response(array('ok'=>false,'error'=>'invalid json: '.json_last_error_msg()), 400);
    if (!class_exists('\\Elementor\\Plugin')) return new WP_REST_Response(array('ok'=>false,'error'=>'elementor not active'), 500);
    $doc = \Elementor\Plugin::$instance->documents->get($p->ID);
    if (!$doc) return new WP_REST_Response(array('ok'=>false,'error'=>'no elementor document'), 500);
    // Token requests have no user, so Elementor's save is blocked by capability checks and the
    // meta sanitizer strips <script>/onclick (no unfiltered_html). Run the save as an admin.
    $prev = get_current_user_id();
    $admins = get_users(array('role'=>'administrator','number'=>1,'fields'=>'ID'));
    if (!empty($admins)) wp_set_current_user((int)$admins[0]);
    kses_remove_filters();
    $doc->save(array('elements' => $decoded));
    kses_init_filters();
    wp_set_current_user($prev);
    $back = get_post_meta($p->ID, '_elementor_data', true);
    $backDecoded = json_decode($back, true);
    return new WP_REST_Response(array(
        'ok'               => true,
        'post_id'          => $p->ID,
        'storedBytes'      => is_string($back) ? strlen($back) : 0,
        'semanticIdentical'=> ($backDecoded == $decoded),
        'scriptsPreserved' => (is_string($back) && strpos($back, 'toggleFaq') !== false),
    ), 200);
}

/* ---- IndexNow: push new/updated URLs to search engines (Bing, Yandex, etc.) ---- */
add_action('init', 'fvc_bridge_indexnow_keyfile');

// Keep the Rank Math sitemap fresh — bridge-published posts were missing from the
// cached sitemap. Disabling the cache makes it regenerate on every request (a 12-post
// site regenerates instantly), so new posts always appear for Google.
add_filter('rank_math/sitemap/enable_caching', '__return_false');
function fvc_bridge_indexnow_keyfile() {
    $key = get_option('fvc_bridge_indexnow_key');
    if ( ! $key ) { $key = bin2hex(random_bytes(16)); update_option('fvc_bridge_indexnow_key', $key, false); }
    if ( ! empty($_SERVER['REQUEST_URI']) && trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/') === $key . '.txt' ) {
        header('Content-Type: text/plain'); echo esc_html($key); exit;
    }
}
function fvc_bridge_indexnow_ping($url) {
    $key = get_option('fvc_bridge_indexnow_key');
    if ( ! $key || ! $url ) return;
    wp_remote_post('https://api.indexnow.org/indexnow', array(
        'headers'  => array('content-type' => 'application/json'),
        'body'     => wp_json_encode(array(
            'host'        => 'findvancouverclinics.com',
            'key'         => $key,
            'keyLocation' => 'https://findvancouverclinics.com/' . $key . '.txt',
            'urlList'     => array($url),
        )),
        'timeout'  => 10,
        'blocking' => false,
    ));
    fvc_bridge_log('indexnow', $url);
}

// Least-privilege role for clinic owners: edit their OWN listing + upload images.
// No publishing new posts, no deleting, no editing others' content.
add_action('init', 'fvc_bridge_register_owner_role');
function fvc_bridge_register_owner_role() {
    if ( get_role('fvc_clinic_owner') ) return;
    add_role('fvc_clinic_owner', 'Clinic Owner', array(
        'read'                 => true,
        'edit_posts'           => true,
        'edit_published_posts' => true,
        'upload_files'         => true,
    ));
}

function fvc_bridge_rest_health() {
    nocache_headers(); // don't let the host proxy-cache this (stale version reads)
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

// Authenticate GitHub requests for our repo (manifest + release zip) when a token
// is set, so self-update keeps working even if the repo is made private.
// Set the token in wp-config.php:  define('FVC_GH_TOKEN', 'ghp_or_fine_grained_token');
add_filter('http_request_args', 'fvc_bridge_github_auth', 10, 2);
// Token from a wp-config constant OR the Settings screen option (set in wp-admin).
function fvc_bridge_gh_token() {
    if ( defined('FVC_GH_TOKEN') && FVC_GH_TOKEN ) return FVC_GH_TOKEN;
    return (string) get_option('fvc_bridge_gh_token', '');
}
function fvc_bridge_github_auth($args, $url) {
    $tok = fvc_bridge_gh_token();
    if ( $tok
        && ( strpos($url, 'github.com/rubenjdelacruz1985-jpg/fvc-bridge') !== false
          || strpos($url, 'api.github.com/repos/rubenjdelacruz1985-jpg/fvc-bridge') !== false ) ) {
        if ( empty($args['headers']) || ! is_array($args['headers']) ) $args['headers'] = array();
        $args['headers']['Authorization'] = 'token ' . $tok;
    }
    return $args;
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

// CASL consent checkbox — injected into the clinic add/claim forms, and wired
// into their fetch() POST so marketing_consent is included only when ticked.
add_action('wp_footer', 'fvc_bridge_consent_injection');
function fvc_bridge_consent_injection() {
    echo <<<'HTML'
<script>(function(){
  function addConsent(){
    if (!document.getElementById('fvc-clinic-name') && !document.getElementById('fvc-email')) return;
    document.querySelectorAll('.fvc-submit-btn').forEach(function(btn){
      if (!btn.parentNode || document.getElementById('fvc-marketing-consent')) return;
      var w = document.createElement('label');
      w.style.cssText = 'display:flex;gap:8px;align-items:flex-start;font-size:14px;margin:14px 0;line-height:1.5;text-align:left;';
      w.innerHTML = '<input type="checkbox" id="fvc-marketing-consent" style="margin-top:3px;flex:none;"><span>Keep me updated with occasional news from Find Vancouver Clinics. See our <a href="/privacy-policy/">Privacy Policy</a>.</span>';
      btn.parentNode.insertBefore(w, btn);
    });
  }
  if (document.readyState !== 'loading') addConsent(); else document.addEventListener('DOMContentLoaded', addConsent);
  var of = window.fetch;
  window.fetch = function(u, o){
    try {
      if (o && o.body instanceof FormData) {
        var a = o.body.get('action');
        if ((a === 'fvc_new_listing' || a === 'fvc_claim') && !o.body.has('marketing_consent')) {
          var cb = document.getElementById('fvc-marketing-consent');
          o.body.append('marketing_consent', (cb && cb.checked) ? '1' : '');
        }
      }
    } catch(e){}
    return of.apply(this, arguments);
  };
})();</script>
HTML;
}

// True on standalone clinic-builder pages (blank canvas) — where directory chrome must NOT appear.
function fvc_bridge_is_standalone() {
    return is_singular() && get_post_meta(get_queried_object_id(), '_wp_page_template', true) === 'elementor_canvas';
}

// Light copy / right-click deterrent on white-label clinic sites (NOT directory or the
// clinic-tools marketing page). Deters casual copying/image-saving; not real DRM (view-source
// and devtools still work), but it stops right-click "save image" and drag-off for most visitors.
add_action('wp_footer', 'fvc_bridge_site_protect', 97);
function fvc_bridge_site_protect() {
    if ( ! fvc_bridge_is_standalone() ) return;
    $slug = get_post_field('post_name', get_queried_object_id());
    if ( in_array($slug, array('clinic-tools'), true) ) return; // marketing page stays selectable
    echo <<<'HTML'
<style id="fvc-protect">
.cs,.cs *{-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;}
.cs input,.cs textarea{-webkit-user-select:text;user-select:text;}
.cs img{-webkit-user-drag:none;-moz-user-drag:none;user-drag:none;}
</style>
<script>(function(){
  var stop=function(e){e.preventDefault();return false;};
  ['contextmenu','dragstart','selectstart','copy','cut'].forEach(function(ev){document.addEventListener(ev,stop);});
  document.addEventListener('keydown',function(e){
    var k=(e.key||'').toLowerCase();
    if((e.ctrlKey||e.metaKey)&&['c','x','s','u','a'].indexOf(k)!==-1){return stop(e);}
  });
})();</script>
HTML;
}

// White-label clinic sites: show ONLY the clinic's name in the browser tab,
// not "... | Find Vancouver Clinics" — so the standalone site feels like the clinic's own.
add_filter('document_title_parts', 'fvc_bridge_standalone_title', 99);
function fvc_bridge_standalone_title($parts) {
    if ( fvc_bridge_is_standalone() ) {
        $t = ( isset($parts['title']) && $parts['title'] !== '' ) ? $parts['title'] : get_the_title();
        return array('title' => $t);
    }
    return $parts;
}
// Rank Math builds the <title> through its own filter — drop the site suffix there too.
add_filter('rank_math/frontend/title', 'fvc_bridge_standalone_rm_title', 99);
function fvc_bridge_standalone_rm_title($title) {
    if ( fvc_bridge_is_standalone() ) {
        $t = get_the_title();
        if ( $t !== '' ) return $t;
    }
    return $title;
}

// Modernize the directory header (sticky glassy bar, gradient pill CTA, pill nav hovers) via a
// scoped CSS overlay — no markup/JS changes, so the dropdown + mobile menu keep working.
// Directory pages only (skipped on white-label clinic sites, which have their own chrome).
add_action('wp_head', 'fvc_bridge_header_css', 31);
function fvc_bridge_header_css() {
    if ( fvc_bridge_is_standalone() ) return;
    echo <<<'HTML'
<style id="fvc-header-modern">
.elementor-location-header{position:sticky!important;top:0!important;z-index:1000!important;}
#fvcNavWrap{background:rgba(9,9,11,.8)!important;-webkit-backdrop-filter:saturate(150%) blur(16px);backdrop-filter:saturate(150%) blur(16px);border-bottom:1px solid rgba(255,255,255,.1)!important;transition:transform .32s ease!important;}
#fvcNavWrap.fvc-hdr-hidden{transform:translateY(-100%)!important;}
#fvcNavWrap .fvc-logo{letter-spacing:-.4px!important;color:#fff!important;}
#fvcNavWrap .fvc-logo-word{color:#fff!important;}
#fvcNavWrap .fvc-logo-accent{color:#12c7c1!important;}
#fvcNavWrap .fvc-nav-link,#fvcNavWrap .fvc-drop-trigger{border-radius:10px!important;font-weight:500!important;color:rgba(255,255,255,.74)!important;transition:background .15s,color .15s!important;}
#fvcNavWrap .fvc-nav-link:hover,#fvcNavWrap .fvc-drop-trigger:hover{background:rgba(255,255,255,.08)!important;color:#fff!important;}
#fvcNavWrap .fvc-cta{background:linear-gradient(135deg,#12c7c1,#0a9b96)!important;color:#fff!important;border:0!important;border-radius:4px!important;box-shadow:0 6px 18px rgba(9,189,184,.3)!important;transition:transform .15s ease,box-shadow .15s ease!important;}
#fvcNavWrap .fvc-cta:hover{transform:translateY(-1px)!important;box-shadow:0 10px 26px rgba(9,189,184,.4)!important;}
/* dark smart mega menu (desktop) */
#fvcNavWrap .fvc-drop-menu{width:680px!important;max-width:calc(100vw - 32px)!important;padding:0!important;border-radius:16px!important;border:1px solid rgba(255,255,255,.1)!important;box-shadow:0 28px 64px rgba(0,0,0,.6)!important;background:rgba(16,16,20,.98)!important;-webkit-backdrop-filter:blur(20px)!important;backdrop-filter:blur(20px)!important;overflow:hidden!important;}
#fvcNavWrap .fvc-dropdown.open .fvc-drop-menu{display:grid!important;grid-template-columns:1.55fr 1fr!important;gap:0!important;}
.fvc-mega-main{padding:18px 16px 16px!important;min-width:0!important;}
.fvc-mega-rail{padding:18px 16px 16px!important;background:rgba(255,255,255,.03)!important;border-left:1px solid rgba(255,255,255,.08)!important;display:flex!important;flex-direction:column!important;}
#fvcNavWrap .fvc-mega-label{display:block!important;font-size:11px!important;font-weight:700!important;letter-spacing:.9px!important;text-transform:uppercase!important;color:rgba(255,255,255,.36)!important;margin:0 0 10px 4px!important;}
.fvc-mega-grid{display:grid!important;grid-template-columns:1fr 1fr!important;gap:3px!important;}
#fvcNavWrap .fvc-mega-grid a{display:flex!important;flex-direction:column!important;align-items:flex-start!important;gap:2px!important;padding:10px 12px!important;border-radius:10px!important;color:#fff!important;border:1px solid transparent!important;transition:background .14s,border-color .14s!important;}
#fvcNavWrap .fvc-mega-grid a:hover{background:rgba(255,255,255,.06)!important;border-color:rgba(255,255,255,.09)!important;}
#fvcNavWrap .fvc-dm-n{font-size:14px!important;font-weight:600!important;color:#fff!important;}
#fvcNavWrap .fvc-dm-d{font-size:12px!important;color:rgba(255,255,255,.5)!important;line-height:1.35!important;font-weight:400!important;}
#fvcNavWrap a.fvc-mega-all{display:inline-flex!important;align-items:center!important;gap:6px!important;margin:12px 0 0 4px!important;font-size:13px!important;font-weight:600!important;color:#12c7c1!important;transition:gap .14s,color .14s!important;}
#fvcNavWrap a.fvc-mega-all:hover{gap:10px!important;color:#4fe8e3!important;}
#fvcNavWrap a.fvc-mega-ql{display:flex!important;align-items:center!important;gap:10px!important;padding:9px 10px!important;border-radius:9px!important;color:rgba(255,255,255,.82)!important;font-size:13.5px!important;font-weight:500!important;transition:background .14s,color .14s!important;}
#fvcNavWrap a.fvc-mega-ql:hover{background:rgba(255,255,255,.06)!important;color:#fff!important;}
.fvc-ql-dot{width:5px!important;height:5px!important;border-radius:50%!important;background:rgba(255,255,255,.28)!important;flex:none!important;transition:background .14s!important;}
#fvcNavWrap a.fvc-mega-ql:hover .fvc-ql-dot{background:#12c7c1!important;}
#fvcNavWrap a.fvc-mega-feat{display:block!important;margin-top:auto!important;padding:14px!important;border-radius:12px!important;background:linear-gradient(135deg,rgba(18,199,193,.16),rgba(10,155,150,.07))!important;border:1px solid rgba(18,199,193,.28)!important;transition:transform .14s,box-shadow .14s!important;}
#fvcNavWrap a.fvc-mega-feat:hover{transform:translateY(-1px)!important;box-shadow:0 8px 22px rgba(9,189,184,.18)!important;}
.fvc-feat-t{display:block!important;font-size:13.5px!important;font-weight:700!important;color:#fff!important;margin-bottom:4px!important;}
.fvc-feat-d{display:block!important;font-size:12px!important;color:rgba(255,255,255,.6)!important;line-height:1.45!important;margin-bottom:8px!important;}
.fvc-feat-c{display:inline-block!important;font-size:12.5px!important;font-weight:600!important;color:#12c7c1!important;}
.fvc-feat-badge,.fvc-mm-chip{display:inline-block!important;font-size:10px!important;font-weight:700!important;letter-spacing:.5px!important;background:linear-gradient(135deg,#12c7c1,#0a9b96)!important;color:#fff!important;padding:2px 6px!important;border-radius:4px!important;margin-left:6px!important;vertical-align:middle!important;}
/* dark smart mobile menu */
#fvcMobileMenu{border-radius:0 0 20px 20px!important;box-shadow:0 26px 54px rgba(0,0,0,.5)!important;padding:6px 20px 16px!important;background:rgba(9,9,11,.98)!important;-webkit-backdrop-filter:blur(18px)!important;backdrop-filter:blur(18px)!important;}
#fvcMobileMenu.open{display:flex!important;flex-direction:column!important;bottom:0!important;z-index:100000!important;overflow-y:auto!important;padding-bottom:16px!important;}
#fvcMobileMenu .fvc-mobile-section-label{font-size:10.5px!important;font-weight:700!important;letter-spacing:.8px!important;text-transform:uppercase!important;color:rgba(255,255,255,.38)!important;margin:13px 0 3px!important;display:block!important;}
#fvcMobileMenu>a{display:block!important;padding:9px 2px!important;font-size:15px!important;font-weight:500!important;color:rgba(255,255,255,.84)!important;border-bottom:1px solid rgba(255,255,255,.07)!important;transition:color .12s!important;}
#fvcMobileMenu>a:hover,#fvcMobileMenu>a:active{color:#4fe8e3!important;}
#fvcMobileMenu .fvc-mm-grid{display:grid!important;grid-template-columns:1fr 1fr!important;gap:6px!important;margin:3px 0 2px!important;}
#fvcMobileMenu .fvc-mm-grid a{display:flex!important;flex-direction:column!important;gap:1px!important;padding:9px 11px!important;border:1px solid rgba(255,255,255,.1)!important;border-radius:8px!important;background:rgba(255,255,255,.03)!important;}
#fvcMobileMenu .fvc-mm-grid a:active{background:rgba(255,255,255,.07)!important;}
#fvcMobileMenu .fvc-dm-n{font-size:14px!important;font-weight:600!important;color:#fff!important;}
#fvcMobileMenu .fvc-dm-d{font-size:11px!important;font-weight:400!important;color:rgba(255,255,255,.45)!important;line-height:1.3!important;}
#fvcMobileMenu>a.fvc-mm-ai{font-weight:600!important;color:#fff!important;}
#fvcMobileMenu .fvc-mobile-divider{display:none!important;}
#fvcMobileMenu>a[data-fvc-area="/clinic-tools/"]{color:#4fe8e3!important;font-weight:700!important;}
#fvcMobileMenu>a.fvc-mm-cta{order:99!important;margin-top:auto!important;text-align:center!important;background:linear-gradient(135deg,#12c7c1,#0a9b96)!important;color:#fff!important;border:0!important;border-bottom:0!important;border-radius:4px!important;padding:13px!important;font-weight:600!important;box-shadow:0 8px 20px rgba(9,189,184,.3)!important;}
/* hamburger -> X when the mobile menu is open */
#fvcHamburger .fvc-hamburger-bar{transition:transform .25s ease,opacity .2s ease!important;}
body:has(#fvcMobileMenu.open) #fvcHamburger .fvc-hamburger-bar:nth-child(1){transform:translateY(7px) rotate(45deg)!important;}
body:has(#fvcMobileMenu.open) #fvcHamburger .fvc-hamburger-bar:nth-child(2){opacity:0!important;}
body:has(#fvcMobileMenu.open) #fvcHamburger .fvc-hamburger-bar:nth-child(3){transform:translateY(-7px) rotate(-45deg)!important;}
/* AI Finder nav link (header) */
#fvcNavWrap a.fvc-nav-ai{display:inline-flex!important;align-items:center!important;gap:6px!important;color:rgba(255,255,255,.9)!important;}
#fvcNavWrap a.fvc-nav-ai:hover{color:#fff!important;}
#fvcNavWrap .fvc-nav-chip{font-size:9px!important;font-weight:700!important;letter-spacing:.5px!important;background:linear-gradient(135deg,#12c7c1,#0a9b96)!important;color:#fff!important;padding:2px 5px!important;border-radius:4px!important;}
/* AI Finder card pinned to the top of the mobile menu */
#fvcMobileMenu>a.fvc-mm-ai-top{display:block!important;margin:6px 0 2px!important;padding:13px 14px!important;border:1px solid rgba(18,199,193,.3)!important;border-bottom:1px solid rgba(18,199,193,.3)!important;border-radius:10px!important;background:linear-gradient(135deg,rgba(18,199,193,.16),rgba(10,155,150,.07))!important;}
#fvcMobileMenu .fvc-mm-ai-t{display:block!important;font-size:15px!important;font-weight:700!important;color:#fff!important;}
#fvcMobileMenu .fvc-mm-ai-d{display:block!important;font-size:12px!important;font-weight:400!important;color:rgba(255,255,255,.6)!important;margin-top:2px!important;}
/* locked type scale: section headings identical across the home page */
.fvc-cats-section h2.fvc-cats-h2,.fvc-cta-section h2.fvc-cta-h2,.fvc-cta-strip .fvc-cta-strip-inner h2,body .fvc-section-h2{font-size:clamp(28px,4.5vw,42px)!important;line-height:1.12!important;letter-spacing:-.03em!important;font-weight:500!important;}
/* heading WEIGHT consistency: site headings are 500 (single-listing 400, claim-CTA 700, blog 400) */
body .fvc-cta-wrap h2{font-weight:500!important;letter-spacing:-.03em!important;}
body.single-post h1,body.single-post h2{font-weight:500!important;}
/* unify inner-page hero title SIZE to one scale (home hero stays large; blog keeps its own size) */
body:not(.home) .fvc-hero-h1,.fvc-cf-h1,body .fvc-sl-title,body:not(.home) .fvc-hero h1{font-size:clamp(28px,4vw,48px)!important;line-height:1.12!important;letter-spacing:-.03em!important;font-weight:500!important;}
/* remove the hero secondary "List your clinic free" button */
body .fvc-hero-btn-secondary{display:none!important;}
/* lock inner-page action buttons to the site's 4px rounded-rect (archive/search/single) */
body .fvc-card-btn,body .fvc-sl-btn,body .fvc-filter-apply,body .fvc-filter-clear{border-radius:4px!important;}
body .fvc-ft-mail-btn{border-radius:0 4px 4px 0!important;}
/* dark bottom search bar — full-width docked (not floating) at all widths */
body #fvc-sb-wrap,html #fvc-sb-wrap{left:0!important;right:0!important;bottom:0!important;width:100%!important;max-width:100%!important;margin:0!important;transform:none!important;border-radius:0!important;padding:11px 24px calc(11px + env(safe-area-inset-bottom,0px))!important;background:#09090b!important;border-top:1px solid rgba(255,255,255,.1)!important;box-shadow:0 -8px 30px rgba(0,0,0,.45)!important;}
#fvc-sb-inner{background:transparent!important;-webkit-backdrop-filter:none!important;backdrop-filter:none!important;border:0!important;border-radius:0!important;box-shadow:none!important;width:100%!important;max-width:860px!important;margin:0 auto!important;}
#fvc-sb-wrap .fvc-sb-btn-toggle{border-radius:4px!important;font-weight:600!important;background:rgba(255,255,255,.07)!important;color:#fff!important;border:1px solid rgba(255,255,255,.14)!important;}
#fvc-sb-wrap #fvc-sb-input{background:rgba(255,255,255,.05)!important;color:#fff!important;border:1px solid rgba(255,255,255,.14)!important;border-radius:4px!important;padding-left:14px!important;padding-right:14px!important;}
#fvc-sb-wrap #fvc-sb-input::placeholder{color:rgba(255,255,255,.5)!important;}
#fvc-sb-wrap #fvc-sb-submit,#fvc-sb-inner #fvc-sb-submit{background:linear-gradient(135deg,#12c7c1,#0a9b96)!important;background-color:#0a9b96!important;color:#fff!important;border:0!important;border-radius:4px!important;box-shadow:0 6px 16px rgba(9,189,184,.3)!important;}
@media(max-width:768px){body #fvc-sb-wrap,html #fvc-sb-wrap{padding-left:12px!important;padding-right:12px!important;box-shadow:0 -10px 30px rgba(0,0,0,.5)!important;}}
body:has(#fvcMobileMenu.open) #fvc-sb-wrap{display:none!important;}
/* --- accessibility: raise low-contrast text toward WCAG AA --- */
body .fvc-hero-breadcrumb,body .fvc-hero-breadcrumb *{color:rgba(255,255,255,.68)!important;}
body .fvc-hero-sub{color:rgba(255,255,255,.66)!important;}
body .fvc-trust-text{color:rgba(255,255,255,.62)!important;}
body .fvc-cats-sub,body .fvc-hood-sub{color:rgba(9,9,11,.66)!important;}
.fvc-card-meta,.fvc-card-meta-item,.fvc-card-row,.fvc-card-service-tag{color:#4f4f57!important;}
.fvc-card-rating-count{color:rgba(0,0,0,.6)!important;}
body .fvc-filter-title{color:rgba(255,255,255,.62)!important;}
.fvc-area-pill{color:rgba(255,255,255,.85)!important;}
/* larger touch targets on mobile (>=44px); View Clinic compact (not full-width) on mobile */
@media(max-width:768px){#fvcNavWrap .fvc-cta{min-height:44px!important;display:inline-flex!important;align-items:center!important;}#fvc-sb-wrap .fvc-sb-btn-toggle,#fvc-sb-wrap #fvc-sb-input,#fvc-sb-wrap #fvc-sb-submit{min-height:44px!important;}.fvc-card-btn{width:auto!important;align-self:flex-start!important;}}
</style>
<script>(function(){
  var DESC={'physiotherapy':'Injury, pain & recovery','chiropractic':'Alignment & manual therapy','massage therapy':'Therapeutic & relaxation','naturopath':'Natural, whole-body care','acupuncture':'Traditional pain & wellness'};
  var QUICK=[{h:'/find-a-clinic-by-area/',l:'Find by area'},{h:'/icbc-approved-clinics-vancouver/',l:'ICBC-approved'},{h:'/worksafebc-approved-clinics-vancouver/',l:'WorkSafeBC-approved'},{h:'/places/',l:'All clinics'}];
  function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
  function services(){
    var out=[],seen={};
    document.querySelectorAll('#fvcDropMenu a').forEach(function(a){
      if(/fvc-mega/.test(a.className||''))return;
      var nEl=a.querySelector('.fvc-dm-n');var name=(nEl?nEl.textContent:(a.textContent||'')).trim();
      var href=a.getAttribute('href');
      if(name&&href&&!seen[href]){seen[href]=1;out.push({name:name,href:href});}
    });
    return out;
  }
  function buildDesktop(svc){
    var menu=document.getElementById('fvcDropMenu');
    if(!menu||menu.getAttribute('data-mega'))return;
    var g='';svc.forEach(function(s){g+='<a href="'+esc(s.href)+'"><span class="fvc-dm-n">'+esc(s.name)+'</span><span class="fvc-dm-d">'+esc(DESC[s.name.toLowerCase()]||'')+'</span></a>';});
    var ql='';QUICK.forEach(function(q){ql+='<a class="fvc-mega-ql" href="'+q.h+'"><span class="fvc-ql-dot"></span><span>'+q.l+'</span></a>';});
    menu.innerHTML='<div class="fvc-mega-main"><span class="fvc-mega-label">Browse by specialty</span><div class="fvc-mega-grid">'+g+'</div><a class="fvc-mega-all" href="/places/">View all clinics <span>&rarr;</span></a></div>'+
      '<div class="fvc-mega-rail"><span class="fvc-mega-label">Quick links</span>'+ql+
      '<a class="fvc-mega-feat" href="/vancouver-clinic-finder/"><span class="fvc-feat-t">AI Clinic Finder <span class="fvc-feat-badge">AI</span></span><span class="fvc-feat-d">Describe your issue &mdash; get matched to the right clinic in seconds.</span><span class="fvc-feat-c">Try it free &rarr;</span></a></div>';
    menu.setAttribute('data-mega','1');
  }
  function buildMobile(svc){
    var mm=document.getElementById('fvcMobileMenu');
    if(!mm||mm.getAttribute('data-mega'))return;
    var h='<a class="fvc-mm-ai-top" href="/vancouver-clinic-finder/"><span class="fvc-mm-ai-t">AI Clinic Finder <span class="fvc-mm-chip">AI</span></span><span class="fvc-mm-ai-d">Describe your issue &mdash; get matched in seconds</span></a>';
    h+='<span class="fvc-mobile-section-label">Browse by specialty</span><div class="fvc-mm-grid">';
    svc.forEach(function(s){h+='<a href="'+esc(s.href)+'"><span class="fvc-dm-n">'+esc(s.name)+'</span><span class="fvc-dm-d">'+esc(DESC[s.name.toLowerCase()]||'')+'</span></a>';});
    h+='</div><span class="fvc-mobile-section-label">Quick links</span>';
    h+='<a class="fvc-mm-ql" data-fvc-area="/find-a-clinic-by-area/" href="/find-a-clinic-by-area/">Find by area</a>';
    h+='<a class="fvc-mm-ql" href="/icbc-approved-clinics-vancouver/">ICBC-approved</a>';
    h+='<a class="fvc-mm-ql" href="/worksafebc-approved-clinics-vancouver/">WorkSafeBC-approved</a>';
    h+='<a class="fvc-mm-ql" href="/places/">All clinics</a>';
    h+='<span class="fvc-mobile-section-label">For clinics</span>';
    h+='<a data-fvc-area="/clinic-tools/" href="/clinic-tools/">For clinics &mdash; tools &amp; free site</a>';
    mm.innerHTML=h;
    mm.setAttribute('data-mega','1');
  }
  function addNavAI(){
    var nav=document.querySelector('nav.fvc-nav');
    if(!nav||nav.querySelector('.fvc-nav-ai'))return;
    var a=document.createElement('a');a.href='/vancouver-clinic-finder/';a.className='fvc-nav-link fvc-nav-ai';a.innerHTML='AI Finder <span class="fvc-nav-chip">AI</span>';
    var drop=document.getElementById('fvcDrop');
    if(drop&&drop.parentNode===nav&&drop.nextSibling)nav.insertBefore(a,drop.nextSibling);else nav.insertBefore(a,nav.firstChild);
  }
  function hideOnScroll(){
    var hdr=document.getElementById('fvcNavWrap');
    if(!hdr)return;
    hdr.style.setProperty('transition','transform .32s ease','important');
    var last=window.pageYOffset||0,ticking=false,hidden=false;
    function show(){if(hidden){hdr.style.setProperty('transform','translateY(0)','important');hidden=false;}}
    function hide(){if(!hidden){hdr.style.setProperty('transform','translateY(-100%)','important');hidden=true;}}
    function upd(){
      var y=window.pageYOffset||0;
      if(document.querySelector('#fvcMobileMenu.open')||y<120)show();
      else if(y>last+4)hide();
      else if(y<last-4)show();
      last=y;ticking=false;
    }
    window.addEventListener('scroll',function(){if(!ticking){requestAnimationFrame(upd);ticking=true;}},{passive:true});
  }
  function dedupeHoods(){
    // the "Browse by neighbourhood" section is duplicated in the page content;
    // keep the first, hide any extra copies.
    var secs=document.querySelectorAll('.fvc-hood-section');
    for(var i=1;i<secs.length;i++)secs[i].style.setProperty('display','none','important');
  }
  function blogHeadings(){
    // blog engine bakes inline font-weight:400!important on headings; the site standard is 500.
    if(!document.body.classList.contains('single-post'))return;
    Array.prototype.forEach.call(document.querySelectorAll('h1,h2,h3'),function(h){
      if(h.closest('header,footer,nav,#fvcNavWrap,#fvcMobileMenu,#fvc-sb-wrap'))return;
      h.style.setProperty('font-weight','500','important');
    });
  }
  function enhance(){
    var svc=services();
    if(svc.length){buildDesktop(svc);buildMobile(svc);}
    addNavAI();
    hideOnScroll();
    blogHeadings();
    dedupeHoods();setTimeout(dedupeHoods,1000);setTimeout(dedupeHoods,2500);
    var dt=document.getElementById('fvcDropTrigger');
    if(dt){for(var i=0;i<dt.childNodes.length;i++){var n=dt.childNodes[i];if(n.nodeType===3&&/clinics/i.test(n.textContent)){n.textContent=n.textContent.replace(/clinics/i,'Services');break;}}}
  }
  if(document.readyState!=='loading')enhance();else document.addEventListener('DOMContentLoaded',enhance);
})();</script>
HTML;
}

// Site credit in the footer (owner-requested): design & build by Thumpy Marketing.
add_action('wp_footer', 'fvc_bridge_footer_credit', 95);
function fvc_bridge_footer_credit() {
    if ( fvc_bridge_is_standalone() ) return; // clinic sites are white-label — no directory credit
    echo <<<'HTML'
<script>(function(){
  function addCredit(){
    if (document.getElementById('fvc-thumpy-credit')) return;
    var f = document.querySelector('.elementor-location-footer') || document.querySelector('[data-elementor-type="footer"]') || document.querySelector('footer');
    var d = document.createElement('div');
    d.id = 'fvc-thumpy-credit';
    d.style.cssText = 'text-align:center;padding:14px 20px 18px;font:400 13px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Arial,sans-serif;color:#8a8a8f;';
    d.innerHTML = 'Website design &amp; build by <a href="https://thumpymarketing.com" target="_blank" rel="noopener" style="color:#09BDB8;text-decoration:none;">Thumpy Marketing</a>';
    if (f) f.appendChild(d); else document.body.appendChild(d);
  }
  if (document.readyState !== 'loading') addCredit(); else document.addEventListener('DOMContentLoaded', addCredit);
})();</script>
HTML;
}

// Add a "Find by Area" link into the header nav, the mobile menu, and the footer
// (all are custom fvc- structures, not WP menus, so we inject to match each one's styling).
add_action('wp_footer', 'fvc_bridge_nav_area_link', 96);
function fvc_bridge_nav_area_link() {
    if ( fvc_bridge_is_standalone() ) return; // no directory nav on white-label clinic sites
    echo <<<'HTML'
<script>(function(){
  var LINKS=[{h:'/find-a-clinic-by-area/',l:'Find by Area'},{h:'/clinic-tools/',l:'For Clinics'}];
  function mk(k,cls){var a=document.createElement('a');a.href=k.h;a.textContent=k.l;if(cls)a.className=cls;a.setAttribute('data-fvc-area',k.h);return a;}
  function add(){
    document.querySelectorAll('nav.fvc-nav').forEach(function(n){LINKS.forEach(function(k){if(!n.querySelector('[data-fvc-area="'+k.h+'"]'))n.appendChild(mk(k,'fvc-nav-link'));});});
    document.querySelectorAll('.fvc-mobile-menu').forEach(function(n){LINKS.forEach(function(k){if(!n.querySelector('[data-fvc-area="'+k.h+'"]'))n.appendChild(mk(k));});});
    var foot=document.querySelector('footer');
    if(foot){var ws=Array.prototype.slice.call(foot.querySelectorAll('a')).filter(function(a){return /worksafebc-approved/.test(a.getAttribute('href')||'');})[0];if(ws&&ws.parentNode){LINKS.forEach(function(k){if(!foot.querySelector('[data-fvc-area="'+k.h+'"]'))ws.parentNode.insertBefore(mk(k,ws.className||''),ws.nextSibling);});}}
  }
  if(document.readyState!=='loading')add();else document.addEventListener('DOMContentLoaded',add);
})();</script>
HTML;
}

// Suppress the legacy WPCode handlers at runtime (priority 0, before they fire),
// so the bridge is the sole handler even if snippets #1071/#1015 are still active.
add_action('wp_ajax_fvc_new_listing',        'fvc_bridge_suppress_legacy', 0);
add_action('wp_ajax_nopriv_fvc_new_listing', 'fvc_bridge_suppress_legacy', 0);
add_action('wp_ajax_fvc_claim',              'fvc_bridge_suppress_legacy', 0);
add_action('wp_ajax_nopriv_fvc_claim',       'fvc_bridge_suppress_legacy', 0);
function fvc_bridge_suppress_legacy() {
    remove_action('wp_ajax_fvc_new_listing',        'fvc_handle_new_listing');
    remove_action('wp_ajax_nopriv_fvc_new_listing', 'fvc_handle_new_listing');
    remove_action('wp_ajax_fvc_claim',              'fvc_handle_claim');
    remove_action('wp_ajax_nopriv_fvc_claim',       'fvc_handle_claim');
}

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
    . '<tr><td style="padding:22px 32px;background:#fafafa;border-top:1px solid #eee;"><p style="margin:0 0 6px;font-size:13px;color:#3f3f46;">Questions? Just reply to this email — a real person reads it.</p><p style="margin:0;font-size:12px;line-height:1.5;color:#9ca3af;">Find Vancouver Clinics &middot; Vancouver, BC &middot; <a href="https://findvancouverclinics.com" style="color:#6b6b6e;">findvancouverclinics.com</a><br>You received this because your clinic was submitted to or listed on our directory.</p></td></tr>'
    . '</table></td></tr></table>';
}

// -- "Your listing is now live" email --
function fvc_bridge_send_live_email($to, $contact, $clinic, $view_url) {
    if ( ! is_email($to) ) return false;
    $inner =
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">Great news, ' . esc_html($contact) . ' — <strong>' . esc_html($clinic) . '</strong> is now live on Find Vancouver Clinics and showing to patients searching your area.</p>'
      . '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 22px;"><tr><td style="border-radius:8px;background:#09BDB8;"><a href="' . esc_url($view_url) . '" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#fff;text-decoration:none;">View your listing &rarr;</a></td></tr></table>'
      . '<p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#3f3f46;">Want to manage it yourself — update hours, services, photos and more? <strong>Claim your listing</strong> to get edit access:</p>'
      . '<p style="margin:0;font-size:14px;"><a href="https://findvancouverclinics.com/claim-listing/" style="color:#0a8f8b;">Claim this listing &rarr;</a></p>';
    $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>', 'Reply-To: Find Vancouver Clinics <claim@findvancouverclinics.com>');
    return wp_mail($to, 'Your clinic is now live on Find Vancouver Clinics', fvc_bridge_email_shell('Your clinic is now live on Find Vancouver Clinics.', 'You\'re live, ' . esc_html($contact) . '.', $inner), $headers);
}

// -- "You're already listed — claim it" email (sent when a submission matches an existing listing) --
function fvc_bridge_send_claim_invite($to, $contact, $clinic, $listing_url) {
    if ( ! is_email($to) ) return false;
    $inner =
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">Thanks for reaching out, ' . esc_html($contact) . '. Good news — <strong>' . esc_html($clinic) . '</strong> already appears on Find Vancouver Clinics, so there\'s no need to add it again:</p>'
      . '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 22px;"><tr><td style="border-radius:8px;background:#09BDB8;"><a href="' . esc_url($listing_url) . '" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#fff;text-decoration:none;">See your current listing &rarr;</a></td></tr></table>'
      . '<p style="margin:0 0 8px;font-size:15px;line-height:1.6;color:#3f3f46;">To take ownership and manage it (hours, services, photos, insurance details), <strong>claim it</strong>:</p>'
      . '<p style="margin:0 0 20px;font-size:14px;"><a href="https://findvancouverclinics.com/claim-listing/" style="color:#0a8f8b;">Claim this listing &rarr;</a></p>'
      . '<div style="background:#f7f7f7;border-left:3px solid #09BDB8;border-radius:6px;padding:14px 16px;">'
      . '<p style="margin:0 0 8px;font-size:13px;font-weight:700;color:#09090B;">How we verify it\'s really you</p>'
      . '<p style="margin:0;font-size:13px;line-height:1.6;color:#3f3f46;">To protect clinics, we confirm ownership before granting edit access. We\'ll verify using one of: an email address on the clinic\'s own domain, a quick call to the clinic\'s publicly listed phone number, or a business document (e.g., licence or a photo of clinic signage). We\'ll be in touch within 1&ndash;2 business days after you claim.</p>'
      . '</div>';
    $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>', 'Reply-To: Find Vancouver Clinics <claim@findvancouverclinics.com>');
    return wp_mail($to, 'Your clinic is already on Find Vancouver Clinics — claim it', fvc_bridge_email_shell('Your clinic is already listed — here\'s how to claim it.', 'You\'re already listed, ' . esc_html($contact) . '.', $inner), $headers);
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
    if ( $match && $match['score'] >= 90 ) {
        // Confident duplicate — point them to the existing listing + how to claim it,
        // instead of the "new listing received" confirmation.
        fvc_bridge_send_claim_invite($d['email'], $d['contact'], $d['clinic_name'], $match['url']);
    } else {
        wp_mail($d['email'], 'We received your listing request - Find Vancouver Clinics', $confirm, $headers);
    }

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
    nocache_headers(); // don't let the host proxy-cache the queue (stale reads)
    global $wpdb;
    $status = sanitize_text_field($req->get_param('status') ?: 'new');
    $table  = fvc_bridge_table();
    $rows   = $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM $table WHERE status = %s ORDER BY created_at DESC LIMIT 200", $status), ARRAY_A);
    return new WP_REST_Response(array('count' => count($rows), 'submissions' => $rows), 200);
}

// REST: token-gated anatomy of an existing published listing, so the create
// endpoint can be built to match GeoDirectory's exact structure.
function fvc_bridge_rest_inspect($req) {
    nocache_headers();
    global $wpdb;
    $pid = absint($req->get_param('post_id'));
    if ( ! $pid ) {
        $pid = (int) $wpdb->get_var("SELECT ID FROM {$wpdb->prefix}posts WHERE post_type='gd_place' AND post_status='publish' ORDER BY ID DESC LIMIT 1");
    }
    if ( ! $pid ) return new WP_REST_Response(array('error' => 'no published gd_place found'), 404);

    $post   = get_post($pid, ARRAY_A);
    $detail = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}geodir_gd_place_detail WHERE post_id = %d", $pid), ARRAY_A);
    $terms  = $wpdb->get_results($wpdb->prepare(
        "SELECT tt.term_taxonomy_id, tt.taxonomy, tt.count, t.term_id, t.name, t.slug
         FROM {$wpdb->prefix}term_relationships tr
         JOIN {$wpdb->prefix}term_taxonomy tt ON tr.term_taxonomy_id = tt.term_taxonomy_id
         JOIN {$wpdb->prefix}terms t ON tt.term_id = t.term_id
         WHERE tr.object_id = %d", $pid), ARRAY_A);
    $meta_keys = $wpdb->get_col($wpdb->prepare("SELECT DISTINCT meta_key FROM {$wpdb->prefix}postmeta WHERE post_id = %d", $pid));

    // Column-name list from the detail table (helps map fields precisely).
    $columns = $wpdb->get_results("SHOW COLUMNS FROM {$wpdb->prefix}geodir_gd_place_detail", ARRAY_A);

    // The full gd_placecategory taxonomy (term_taxonomy_id ↔ slug), for category mapping.
    $categories = $wpdb->get_results(
        "SELECT tt.term_taxonomy_id, t.term_id, t.name, t.slug
         FROM {$wpdb->prefix}term_taxonomy tt
         JOIN {$wpdb->prefix}terms t ON tt.term_id = t.term_id
         WHERE tt.taxonomy = 'gd_placecategory'", ARRAY_A);

    return new WP_REST_Response(array(
        'template_post_id' => $pid,
        'post'             => $post ? array_intersect_key($post, array_flip(array('ID','post_author','post_status','post_type','post_title','post_name','post_date','post_content'))) : null,
        'detail_columns'   => array_map(function ($c) { return array('name' => $c['Field'], 'type' => $c['Type'], 'null' => $c['Null'], 'default' => $c['Default']); }, $columns),
        'detail_sample'    => $detail,
        'terms_on_sample'  => $terms,
        'meta_keys'        => $meta_keys,
        'all_categories'   => $categories,
    ), 200);
}

// REST: publish a stored, approved submission BY ID into a live GeoDirectory
// listing. Never accepts listing content in the request — only the id; all
// data comes from the bridge's own store. Idempotent (won't publish twice).
function fvc_bridge_rest_create_listing($req) {
    global $wpdb;

    // Per-token rate limit (require_token already limits per IP).
    $thash = hash('sha256', fvc_bridge_bearer_token());
    $tkey  = 'fvc_bridge_pub_rl_' . $thash;
    $tc    = (int) get_transient($tkey);
    if ( $tc > 20 ) { fvc_bridge_log('create-listing-ratelimited', ''); return new WP_REST_Response(array('ok' => false, 'error' => 'rate_limited'), 429); }
    set_transient($tkey, $tc + 1, MINUTE_IN_SECONDS);

    $p   = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $sid = absint($p['submission_id'] ?? 0);
    if ( ! $sid ) return new WP_REST_Response(array('ok' => false, 'error' => 'submission_id required'), 400);

    $table = fvc_bridge_table();
    $sub   = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $sid), ARRAY_A);
    if ( ! $sub ) { fvc_bridge_log('create-listing-notfound', 'id=' . $sid); return new WP_REST_Response(array('ok' => false, 'error' => 'submission not found'), 404); }
    if ( $sub['type'] !== 'add' ) return new WP_REST_Response(array('ok' => false, 'error' => 'only add-type submissions create listings'), 400);
    if ( $sub['status'] === 'published' ) { fvc_bridge_log('create-listing-dupe', 'id=' . $sid); return new WP_REST_Response(array('ok' => false, 'error' => 'already published', 'post_id' => (int) $sub['matched_post_id']), 409); }

    // Categories from the submitted services (a clinic can be in several).
    $services = strtolower((string) $sub['services']);
    $cats = array();
    foreach ( array('physio' => 7, 'chiro' => 16, 'massage' => 17, 'naturopath' => 18, 'acupunctur' => 19) as $kw => $id ) {
        if ( strpos($services, $kw) !== false ) $cats[] = $id;
    }
    if ( empty($cats) ) $cats = array(7);
    $cat = $cats[0]; // primary category

    $flag   = function ($v) { $v = strtolower((string) $v); return ($v === 'yes' || $v === '1') ? 1 : 0; };
    $status = (isset($p['status']) && $p['status'] === 'draft') ? 'draft' : 'publish';

    $post_id = wp_insert_post(array(
        'post_type' => 'gd_place', 'post_status' => $status,
        'post_title' => $sub['clinic_name'], 'post_content' => '', 'post_author' => 1,
    ), true);
    if ( is_wp_error($post_id) ) { fvc_bridge_log('create-listing-failed', $post_id->get_error_message()); return new WP_REST_Response(array('ok' => false, 'error' => $post_id->get_error_message()), 500); }

    // Detail row — matches the structure learned from an existing listing.
    $wpdb->replace($wpdb->prefix . 'geodir_gd_place_detail', array(
        'post_id'                  => $post_id,
        'post_title'               => $sub['clinic_name'],
        '_search_title'            => strtolower($sub['clinic_name']),
        'post_status'              => $status,
        'post_tags'                => '',
        'post_category'            => ',' . implode(',', $cats) . ',',
        'default_category'         => $cat,
        'featured'                 => 0,
        'overall_rating'           => 0,
        'rating_count'             => 0,
        'street'                   => (string) $sub['address'],
        'street2'                  => '',
        'city'                     => 'Vancouver',
        'region'                   => 'British Columbia',
        'country'                  => 'Canada',
        'zip'                      => '',
        'icbc_approved'            => $flag($sub['icbc']),
        '_worksafebc_approved'     => $flag($sub['worksafe']),
        'direct_billing'           => $flag($sub['billing']),
        'online_booking_available' => $flag($sub['booking']),
        'website'                  => (string) $sub['website'],
        'l'                        => (string) $sub['phone'],
        'email'                    => '',
        'business_status'          => 'OPERATIONAL',
        'enrichment_status'        => 'pending',
    ));

    // Category term relationships + counts (one listing can be in multiple categories).
    foreach ( $cats as $c ) {
        $wpdb->query($wpdb->prepare("INSERT IGNORE INTO {$wpdb->prefix}term_relationships (object_id, term_taxonomy_id, term_order) VALUES (%d, %d, 0)", $post_id, $c));
        $wpdb->query($wpdb->prepare("UPDATE {$wpdb->prefix}term_taxonomy SET count = count + 1 WHERE term_taxonomy_id = %d", $c));
    }

    // Mark the submission published so it can never be published twice.
    $wpdb->update($table, array('status' => 'published', 'matched_post_id' => $post_id), array('id' => $sid));

    // Email the clinic that they're now live (default on; pass notify:false to skip).
    $notified = false;
    if ( ($p['notify'] ?? true) && $status === 'publish' && is_email($sub['email']) ) {
        $notified = fvc_bridge_send_live_email($sub['email'], $sub['contact_name'], $sub['clinic_name'], get_permalink($post_id));
        fvc_bridge_log('notify-live', "sid=$sid to=" . $sub['email'] . " sent=" . ($notified ? '1' : '0'));
    }

    if ( $status === 'publish' ) fvc_bridge_indexnow_ping(get_permalink($post_id));
    fvc_bridge_log('create-listing', "sid=$sid post=$post_id status=$status cats=" . implode('+', $cats));
    return new WP_REST_Response(array(
        'ok' => true, 'submission_id' => $sid, 'post_id' => $post_id,
        'status' => $status, 'categories' => $cats, 'notified' => $notified,
        'view' => get_permalink($post_id), 'edit' => admin_url('post.php?post=' . $post_id . '&action=edit'),
    ), 200);
}

// REST: send the "your listing is now live" email for a published listing, to a
// given address. Only sends the fixed template, only for a published gd_place.
function fvc_bridge_rest_notify_live($req) {
    $p       = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $post_id = absint($p['post_id'] ?? 0);
    $email   = sanitize_email($p['email'] ?? '');
    $contact = sanitize_text_field($p['contact'] ?? 'there');
    if ( ! $post_id || ! is_email($email) ) return new WP_REST_Response(array('ok' => false, 'error' => 'post_id and a valid email required'), 400);

    $post = get_post($post_id);
    if ( ! $post || $post->post_type !== 'gd_place' || $post->post_status !== 'publish' ) {
        return new WP_REST_Response(array('ok' => false, 'error' => 'not a published listing'), 400);
    }
    $sent = fvc_bridge_send_live_email($email, $contact, $post->post_title, get_permalink($post_id));
    fvc_bridge_log('notify-live-manual', "post=$post_id to=$email sent=" . ($sent ? '1' : '0'));
    return new WP_REST_Response(array('ok' => (bool) $sent, 'post_id' => $post_id, 'to' => $email), 200);
}

// REST: approve a stored CLAIM by ID — give the owner edit access to that listing.
// Creates a least-privilege user if needed (they set their own password via WP),
// makes them the listing's author, marks the claim approved, and emails them.
function fvc_bridge_rest_approve_claim($req) {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/user.php';

    $p = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $sid = absint($p['submission_id'] ?? 0);
    if ( ! $sid ) return new WP_REST_Response(array('ok' => false, 'error' => 'submission_id required'), 400);

    $table = fvc_bridge_table();
    $sub = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $sid), ARRAY_A);
    if ( ! $sub ) return new WP_REST_Response(array('ok' => false, 'error' => 'submission not found'), 404);
    if ( $sub['type'] !== 'claim' ) return new WP_REST_Response(array('ok' => false, 'error' => 'only claim submissions can be approved'), 400);
    if ( $sub['status'] === 'approved' ) return new WP_REST_Response(array('ok' => false, 'error' => 'already approved'), 409);

    $listing_id = absint($sub['matched_post_id']);
    if ( ! $listing_id ) {
        $m = fvc_bridge_find_match(array('name' => $sub['clinic_name']));
        if ( $m ) $listing_id = (int) $m['post_id'];
    }
    if ( ! $listing_id ) return new WP_REST_Response(array('ok' => false, 'error' => 'no matching listing to claim'), 400);

    $email = sanitize_email($sub['email']);
    if ( ! is_email($email) ) return new WP_REST_Response(array('ok' => false, 'error' => 'submission has no valid email'), 400);

    $user     = get_user_by('email', $email);
    $new_user = false;
    if ( ! $user ) {
        $uid = wp_insert_user(array(
            'user_login'   => $email,
            'user_email'   => $email,
            'user_pass'    => wp_generate_password(24, true, true),
            'display_name' => $sub['contact_name'] ? $sub['contact_name'] : $email,
            'role'         => 'fvc_clinic_owner',
        ));
        if ( is_wp_error($uid) ) return new WP_REST_Response(array('ok' => false, 'error' => $uid->get_error_message()), 500);
        $new_user = true;
        wp_new_user_notification($uid, null, 'user'); // WP sends a "set your password" link; we never handle the password.
        $user = get_user_by('id', $uid);
    }

    // Make them the listing's author so they can edit it. We never change an
    // existing user's role here (so an admin who happens to match isn't downgraded).
    wp_update_post(array('ID' => $listing_id, 'post_author' => $user->ID));
    $wpdb->update($table, array('status' => 'approved', 'matched_post_id' => $listing_id), array('id' => $sid));

    fvc_bridge_send_claim_approved($email, $sub['contact_name'], $sub['clinic_name'], get_permalink($listing_id), $new_user);
    // Auto-generate a starter clinic site (only if they don't already have one); owner refines it in the builder.
    if ( function_exists('fvc_bridge_generate_site') && ! get_post_meta($listing_id, '_fvc_site_page', true) ) {
        $gen = fvc_bridge_generate_site($listing_id, $user->ID);
        fvc_bridge_log('auto-generate', is_wp_error($gen) ? ('err=' . $gen->get_error_message()) : ('site=' . $gen[0]));
    }
    fvc_bridge_log('approve-claim', "sid=$sid user={$user->ID} post=$listing_id new_user=" . ($new_user ? '1' : '0'));

    return new WP_REST_Response(array(
        'ok' => true, 'submission_id' => $sid, 'user_id' => $user->ID,
        'post_id' => $listing_id, 'new_user' => $new_user, 'view' => get_permalink($listing_id),
    ), 200);
}

// REST: publish a blog post (SEO content). Idempotent-ish by slug (updates an
// existing post with the same slug instead of creating duplicates).
function fvc_bridge_rest_publish_post($req) {
    $p = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $title   = sanitize_text_field($p['title'] ?? '');
    // raw_html: store trusted authored HTML verbatim (allows <style>, grid, hover) — token-gated, no user input.
    $raw     = ! empty($p['raw_html']);
    $content = isset($p['content']) ? ($raw ? (string) $p['content'] : wp_kses_post($p['content'])) : '';
    if ( ! $title || ! $content ) return new WP_REST_Response(array('ok' => false, 'error' => 'title and content required'), 400);

    $status = (isset($p['status']) && $p['status'] === 'draft') ? 'draft' : 'publish';
    $slug   = ! empty($p['slug']) ? sanitize_title($p['slug']) : sanitize_title($title);
    $post_type = (isset($p['post_type']) && $p['post_type'] === 'page') ? 'page' : 'post';

    $existing = get_page_by_path($slug, OBJECT, $post_type);
    $postarr = array(
        'post_type'    => $post_type,
        'post_status'  => $status,
        'post_title'   => $title,
        'post_content' => wp_slash($content), // wp_insert_post unslashes; slash first so backslashes (JSON/JS) survive
        'post_excerpt' => sanitize_text_field($p['excerpt'] ?? ''),
        'post_name'    => $slug,
        'post_author'  => 1,
    );
    if ( $existing ) $postarr['ID'] = $existing->ID;

    // wp_insert_post applies KSES (strips <style> etc.) for users without unfiltered_html.
    // For trusted raw_html content, lift KSES around the insert, then restore it.
    if ( $raw ) kses_remove_filters();
    $post_id = wp_insert_post($postarr, true);
    if ( $raw ) kses_init_filters();
    if ( is_wp_error($post_id) ) return new WP_REST_Response(array('ok' => false, 'error' => $post_id->get_error_message()), 500);

    if ( $post_type === 'post' && ! empty($p['category']) ) {
        $cat = is_numeric($p['category']) ? (int) $p['category'] : get_cat_ID(sanitize_text_field($p['category']));
        if ( $cat ) wp_set_post_categories($post_id, array($cat));
    }
    if ( isset($p['template']) ) {
        update_post_meta($post_id, '_wp_page_template', sanitize_text_field($p['template']));
    }
    if ( ! empty($p['meta_description']) && function_exists('update_post_meta') ) {
        update_post_meta($post_id, 'rank_math_description', sanitize_text_field($p['meta_description']));
    }
    // Custom JSON-LD schema (FAQ, ItemList, etc.) — stored base64 (avoids slash/quote mangling),
    // emitted in <head> by fvc_bridge_output_schema(). WP strips <script> from content, so we can't inline it.
    if ( array_key_exists('schema_jsonld', $p) ) {
        $sraw = is_string($p['schema_jsonld']) ? $p['schema_jsonld'] : wp_json_encode($p['schema_jsonld']);
        if ( $sraw && json_decode($sraw) !== null ) {
            update_post_meta($post_id, '_fvc_schema_b64', base64_encode($sraw));
        } else {
            delete_post_meta($post_id, '_fvc_schema_b64');
        }
    }
    if ( $raw ) { update_post_meta($post_id, '_fvc_raw_html', 1); } else { delete_post_meta($post_id, '_fvc_raw_html'); }

    if ( $status === 'publish' ) fvc_bridge_indexnow_ping(get_permalink($post_id));
    fvc_bridge_log('publish-post', "post=$post_id status=$status " . ($existing ? 'updated' : 'created') . " title=$title");
    return new WP_REST_Response(array(
        'ok' => true, 'post_id' => $post_id, 'status' => $status, 'updated' => (bool) $existing,
        'view' => get_permalink($post_id), 'edit' => admin_url('post.php?post=' . $post_id . '&action=edit'),
    ), 200);
}

// REST: set a post's featured image from a base64-encoded image (PNG/JPG).
function fvc_bridge_rest_set_featured_image($req) {
    require_once ABSPATH . 'wp-admin/includes/image.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';

    $p = $req->get_json_params();
    if ( ! is_array($p) ) $p = $req->get_params();
    $post_id  = absint($p['post_id'] ?? 0);
    if ( ! $post_id || ! get_post($post_id) ) return new WP_REST_Response(array('ok' => false, 'error' => 'valid post_id required'), 400);

    // Reuse an existing media-library image by id (from /media).
    $att = absint($p['attachment_id'] ?? 0);
    if ( $att && get_post($att) ) {
        set_post_thumbnail($post_id, $att);
        fvc_bridge_log('set-featured-image', "post=$post_id attach=$att (existing)");
        return new WP_REST_Response(array('ok' => true, 'post_id' => $post_id, 'attachment_id' => $att, 'url' => wp_get_attachment_url($att)), 200);
    }

    $b64      = $p['image_base64'] ?? '';
    $filename = sanitize_file_name($p['filename'] ?? 'featured.png');
    $alt      = sanitize_text_field($p['alt'] ?? '');
    if ( ! $b64 ) return new WP_REST_Response(array('ok' => false, 'error' => 'image_base64 or attachment_id required'), 400);

    $data = base64_decode($b64, true);
    if ( $data === false ) return new WP_REST_Response(array('ok' => false, 'error' => 'invalid base64'), 400);

    $upload = wp_upload_bits($filename, null, $data);
    if ( ! empty($upload['error']) ) return new WP_REST_Response(array('ok' => false, 'error' => $upload['error']), 500);

    $filetype  = wp_check_filetype($upload['file']);
    $attach_id = wp_insert_attachment(array(
        'post_mime_type' => $filetype['type'],
        'post_title'     => $alt ? $alt : $filename,
        'post_content'   => '',
        'post_status'    => 'inherit',
    ), $upload['file'], $post_id);
    if ( is_wp_error($attach_id) ) return new WP_REST_Response(array('ok' => false, 'error' => $attach_id->get_error_message()), 500);

    wp_update_attachment_metadata($attach_id, wp_generate_attachment_metadata($attach_id, $upload['file']));
    if ( $alt ) update_post_meta($attach_id, '_wp_attachment_image_alt', $alt);
    set_post_thumbnail($post_id, $attach_id);

    fvc_bridge_log('set-featured-image', "post=$post_id attach=$attach_id");
    return new WP_REST_Response(array('ok' => true, 'post_id' => $post_id, 'attachment_id' => $attach_id, 'url' => wp_get_attachment_url($attach_id)), 200);
}

// REST: list recent media-library images so existing photos can be reused.
function fvc_bridge_rest_media($req) {
    nocache_headers();
    $search = sanitize_text_field($req->get_param('search') ?: '');
    $q = new WP_Query(array(
        'post_type'      => 'attachment',
        'post_status'    => 'inherit',
        'post_mime_type' => 'image',
        'posts_per_page' => 80,
        'orderby'        => 'date',
        'order'          => 'DESC',
        's'              => $search,
    ));
    $out = array();
    foreach ( $q->posts as $a ) {
        $out[] = array(
            'id'    => $a->ID,
            'title' => $a->post_title,
            'alt'   => get_post_meta($a->ID, '_wp_attachment_image_alt', true),
            'file'  => basename(get_attached_file($a->ID)),
            'url'   => wp_get_attachment_url($a->ID),
        );
    }
    return new WP_REST_Response(array('count' => count($out), 'media' => $out), 200);
}

// -- "You can now manage your listing" email (claim approved) --
function fvc_bridge_send_claim_approved($to, $contact, $clinic, $view_url, $new_user) {
    if ( ! is_email($to) ) return false;
    $setup = $new_user
        ? '<p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#3f3f46;">We&#39;ve set up your account. Look for a separate email from us to <strong>set your password</strong>, then sign in to edit your listing.</p>'
        : '<p style="margin:0 0 8px;font-size:14px;line-height:1.6;color:#3f3f46;">Sign in with your existing account to edit your listing.</p>';
    $inner =
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">You&#39;re verified, ' . esc_html($contact) . ' — you now have access to manage <strong>' . esc_html($clinic) . '</strong> on Find Vancouver Clinics.</p>'
      . $setup
      . '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:12px 0 8px;"><tr><td style="border-radius:8px;background:#09BDB8;"><a href="' . esc_url($view_url) . '" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#fff;text-decoration:none;">View your listing &rarr;</a></td></tr></table>'
      . '<div style="margin:20px 0 4px;background:#f0fbfa;border:1px solid #cdeeec;border-radius:10px;padding:16px 18px;">'
        . '<p style="margin:0 0 6px;font-size:14px;font-weight:700;color:#0a3d3b;">Your free clinic tools are ready</p>'
        . '<p style="margin:0 0 12px;font-size:13.5px;line-height:1.6;color:#3f3f46;">Build a professional <strong>website</strong>, take <strong>online bookings</strong> with a built-in <strong>calendar</strong>, grow your <strong>Google reviews</strong>, and run a free <strong>SEO checkup</strong> &mdash; all free, no code.</p>'
        . '<a href="https://findvancouverclinics.com/clinic-editor/" style="display:inline-block;padding:10px 18px;border-radius:999px;background:#09BDB8;color:#fff;font-size:14px;font-weight:600;text-decoration:none;">Build my free site &rarr;</a>'
      . '</div>'
      . '<p style="margin:16px 0 0;font-size:13px;color:#6b6b6e;">Sign in at <a href="https://findvancouverclinics.com/wp-login.php" style="color:#0a8f8b;">findvancouverclinics.com/wp-login.php</a> to update your hours, services, and details.</p>';
    $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>', 'Reply-To: Find Vancouver Clinics <claim@findvancouverclinics.com>');
    return wp_mail($to, 'You can now manage your listing on Find Vancouver Clinics', fvc_bridge_email_shell('You&#39;re verified — you can now manage your listing.', 'You&#39;re verified, ' . esc_html($contact) . '.', $inner), $headers);
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
        } elseif ( $_POST['fvc_bridge_action'] === 'save_gh_token' ) {
            update_option('fvc_bridge_gh_token', sanitize_text_field($_POST['gh_token'] ?? ''), false);
            fvc_bridge_log('gh-token-set', '');
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

    // GitHub token — lets self-update work if the repo is made private.
    $gh_set = fvc_bridge_gh_token() ? 'Set &#10003;' : 'Not set';
    echo '<hr><h2>GitHub token <span style="font-weight:400;color:#666;">(only needed if the plugin repo is private)</span></h2>';
    echo '<p>Status: <strong>' . $gh_set . '</strong>. Paste a GitHub <em>fine-grained</em> token with <strong>Contents: Read-only</strong> on the <code>fvc-bridge</code> repo. Stored server-side; never shown again.</p>';
    echo '<form method="post">';
    wp_nonce_field('fvc_bridge_settings');
    echo '<input type="hidden" name="fvc_bridge_action" value="save_gh_token">';
    echo '<input type="password" name="gh_token" placeholder="github_pat_… or ghp_…" class="regular-text" autocomplete="off"> ';
    echo '<button class="button" type="submit">Save token</button></form>';
    echo '</div>';
}

/* ============================================================
 *  Submissions queue (wp-admin) — publish / approve / dismiss
 * ============================================================ */

add_action('admin_menu', function () {
    add_menu_page('FVC Submissions', 'FVC Submissions', 'manage_options', 'fvc-submissions', 'fvc_bridge_submissions_page', 'dashicons-list-view', 26);
});

// Reuse a REST endpoint from inside wp-admin (admin-gated; no token needed).
function fvc_bridge_internal_call($method, $route, $params) {
    $GLOBALS['fvc_bridge_internal'] = true;
    $req = new WP_REST_Request($method, $route);
    $req->set_body_params($params);
    $res = rest_do_request($req);
    $GLOBALS['fvc_bridge_internal'] = false;
    return $res->get_data();
}

function fvc_bridge_submissions_page() {
    if ( ! current_user_can('manage_options') ) return;
    global $wpdb;
    $notice = '';

    if ( isset($_POST['fvc_sub_action']) && check_admin_referer('fvc_submissions') ) {
        $sid = absint($_POST['sid'] ?? 0);
        $act = sanitize_text_field($_POST['fvc_sub_action']);
        if ( $act === 'publish' ) {
            $r = fvc_bridge_internal_call('POST', '/fvc-bridge/v1/create-listing', array('submission_id' => $sid));
            $notice = ! empty($r['ok']) ? 'Published &amp; the clinic was emailed: <a href="' . esc_url($r['view']) . '">' . esc_html($r['view']) . '</a>' : 'Error: ' . esc_html($r['error'] ?? 'unknown');
        } elseif ( $act === 'approve' ) {
            $r = fvc_bridge_internal_call('POST', '/fvc-bridge/v1/approve-claim', array('submission_id' => $sid));
            $notice = ! empty($r['ok']) ? 'Approved — the owner was granted edit access and emailed.' : 'Error: ' . esc_html($r['error'] ?? 'unknown');
        } elseif ( $act === 'dismiss' ) {
            $wpdb->update(fvc_bridge_table(), array('status' => 'dismissed'), array('id' => $sid));
            $notice = 'Dismissed.';
        }
    }

    $rows = $wpdb->get_results("SELECT * FROM " . fvc_bridge_table() . " WHERE status = 'new' ORDER BY created_at DESC LIMIT 200", ARRAY_A);

    // Flag submissions that duplicate ANOTHER pending submission (same clinic in the queue).
    $norm = array();
    foreach ( $rows as $i => $r ) {
        $norm[$i] = array(
            'name'   => fvc_bridge_norm_name($r['clinic_name']),
            'domain' => fvc_bridge_norm_domain($r['website']),
            'phone'  => fvc_bridge_norm_phone($r['phone']),
        );
    }
    $intra = array();
    foreach ( $rows as $i => $r ) {
        foreach ( $rows as $j => $r2 ) {
            if ( $i >= $j ) continue;
            $a = $norm[$i]; $b = $norm[$j];
            if ( ( $a['domain'] && $a['domain'] === $b['domain'] )
              || ( $a['phone'] && $a['phone'] === $b['phone'] )
              || ( $a['name'] && $a['name'] === $b['name'] ) ) {
                $intra[$i][] = (int) $r2['id'];
                $intra[$j][] = (int) $r['id'];
            }
        }
    }

    echo '<div class="wrap"><h1>FVC Submissions</h1>';
    if ( $notice ) echo '<div class="notice notice-info"><p>' . $notice . '</p></div>';
    if ( ! $rows ) { echo '<p>No new submissions right now. &#127881;</p></div>'; return; }

    echo '<table class="widefat striped"><thead><tr><th>Type</th><th>Clinic</th><th>Contact</th><th>Possible duplicate</th><th>Action</th></tr></thead><tbody>';
    foreach ( $rows as $i => $r ) {
        $dup = $r['matched_post_id'] ? 'matches listing #' . (int) $r['matched_post_id'] . ' (score ' . (int) $r['match_score'] . ')' : '&mdash;';
        if ( ! empty($intra[$i]) ) {
            $dup .= '<br><span style="color:#b26a00;">&#9888; also in queue as #' . esc_html(implode(', #', array_unique($intra[$i]))) . '</span>';
        }
        echo '<tr>';
        echo '<td><span class="dashicons ' . ($r['type'] === 'claim' ? 'dashicons-admin-users' : 'dashicons-plus') . '"></span> ' . esc_html($r['type']) . '</td>';
        echo '<td><strong>' . esc_html($r['clinic_name']) . '</strong><br><span style="color:#666">' . esc_html($r['website']) . '</span></td>';
        echo '<td>' . esc_html($r['contact_name']) . '<br><span style="color:#666">' . esc_html($r['email']) . '</span></td>';
        echo '<td>' . $dup . '</td>';
        echo '<td><form method="post" style="margin:0">';
        wp_nonce_field('fvc_submissions');
        echo '<input type="hidden" name="sid" value="' . (int) $r['id'] . '">';
        if ( $r['type'] === 'add' ) {
            echo '<button class="button button-primary" name="fvc_sub_action" value="publish">Publish</button> ';
        } else {
            echo '<button class="button button-primary" name="fvc_sub_action" value="approve">Approve claim</button> ';
        }
        echo '<button class="button" name="fvc_sub_action" value="dismiss" onclick="return confirm(\'Dismiss this submission?\')">Dismiss</button>';
        echo '</form></td></tr>';
    }
    echo '</tbody></table></div>';
}

// ============================================================
//  Booking v1 (native) — services, availability, appointments,
//  confirmation emails + .ics, and an iCal subscription feed.
//  Patient PII is minimal + consented (PIPA-aware). No payments here
//  (Stripe Checkout is a separate, keys-required add-on).
// ============================================================
function fvc_bridge_booking_table() { global $wpdb; return $wpdb->prefix . 'fvc_appointments'; }

function fvc_bridge_booking_ensure_table() {
    global $wpdb;
    $t = fvc_bridge_booking_table();
    if ( get_option('fvc_bridge_booking_db') === '2' ) return;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $charset = $wpdb->get_charset_collate();
    dbDelta("CREATE TABLE $t (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        listing_id BIGINT UNSIGNED NOT NULL,
        service VARCHAR(160) DEFAULT '',
        practitioner VARCHAR(160) DEFAULT '',
        start_local DATETIME NOT NULL,
        end_local DATETIME NOT NULL,
        name VARCHAR(160) DEFAULT '',
        email VARCHAR(190) DEFAULT '',
        phone VARCHAR(60) DEFAULT '',
        notes TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        manage_key VARCHAR(40) DEFAULT '',
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY listing_id (listing_id),
        KEY start_local (start_local)
    ) $charset;");
    update_option('fvc_bridge_booking_db', '2');
}

function fvc_bridge_booking_defaults($listing_id) {
    $cats = wp_get_post_terms($listing_id, 'gd_placecategory', array('fields' => 'names'));
    $svc = array();
    foreach ( (array) $cats as $c ) { $svc[] = array('name' => $c, 'duration' => 45, 'price' => 0); }
    if ( ! $svc ) $svc[] = array('name' => 'Appointment', 'duration' => 45, 'price' => 0);
    return array(
        'enabled' => true, 'externalUrl' => '',
        'services' => $svc, 'practitioners' => array(),
        'hours' => array(
            'mon' => array('09:00','17:00'), 'tue' => array('09:00','17:00'),
            'wed' => array('09:00','17:00'), 'thu' => array('09:00','19:00'),
            'fri' => array('09:00','17:00'), 'sat' => array('10:00','14:00'), 'sun' => array(),
        ),
        'slotMinutes' => 45, 'timezone' => 'America/Vancouver',
    );
}
function fvc_bridge_booking_get_config($listing_id) {
    $c = get_post_meta($listing_id, '_fvc_booking', true);
    if ( is_array($c) && ! empty($c) ) return array_merge(fvc_bridge_booking_defaults($listing_id), $c);
    return fvc_bridge_booking_defaults($listing_id);
}
function fvc_bridge_booking_owns($listing_id) {
    if ( fvc_bridge_has_valid_token() || current_user_can('manage_options') ) return true;
    $p = get_post($listing_id); $uid = get_current_user_id();
    return $p && $uid && (int) $p->post_author === $uid;
}

function fvc_bridge_rest_booking_config($req) {
    $id = (int) $req->get_param('listing');
    if ( ! $id ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing required'), 400);
    $p = get_post($id);
    if ( ! $p || $p->post_type !== 'gd_place' ) return new WP_REST_Response(array('ok' => false, 'error' => 'not found'), 404);
    $cfg = fvc_bridge_booking_get_config($id);
    $cfg['ok'] = true; $cfg['listingId'] = $id; $cfg['clinic'] = html_entity_decode($p->post_title, ENT_QUOTES);
    return new WP_REST_Response($cfg, 200);
}
function fvc_bridge_rest_booking_config_save($req) {
    $b = $req->get_json_params(); $id = (int) ($b['listing_id'] ?? 0);
    if ( ! $id || ! fvc_bridge_booking_owns($id) ) return new WP_REST_Response(array('ok' => false, 'error' => 'not allowed'), 403);
    $cfg = array(
        'enabled' => ! empty($b['enabled']),
        'externalUrl' => esc_url_raw($b['externalUrl'] ?? ''),
        'services' => array_values(array_map(function ($s) {
            return array('name' => sanitize_text_field($s['name'] ?? ''), 'duration' => max(15, (int) ($s['duration'] ?? 45)), 'price' => max(0, (float) ($s['price'] ?? 0)));
        }, (array) ($b['services'] ?? array()))),
        'practitioners' => array_values(array_map('sanitize_text_field', (array) ($b['practitioners'] ?? array()))),
        'hours' => (array) ($b['hours'] ?? array()),
        'slotMinutes' => max(15, (int) ($b['slotMinutes'] ?? 45)),
        'timezone' => sanitize_text_field($b['timezone'] ?? 'America/Vancouver'),
    );
    update_post_meta($id, '_fvc_booking', $cfg);
    return new WP_REST_Response(array('ok' => true), 200);
}

function fvc_bridge_rest_booking_slots($req) {
    $id = (int) $req->get_param('listing');
    $date = preg_replace('/[^0-9\-]/', '', (string) $req->get_param('date'));
    $pract = sanitize_text_field((string) $req->get_param('practitioner'));
    if ( ! $id || ! $date ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing+date required'), 400);
    $cfg = fvc_bridge_booking_get_config($id);
    $svcMin = (int) $cfg['slotMinutes'];
    $svcName = sanitize_text_field((string) $req->get_param('service'));
    foreach ( $cfg['services'] as $s ) { if ( $s['name'] === $svcName ) { $svcMin = (int) $s['duration']; break; } }
    if ( $svcMin < 15 ) $svcMin = 45;
    $tz = new DateTimeZone($cfg['timezone']);
    $day = DateTime::createFromFormat('Y-m-d', $date, $tz);
    if ( ! $day ) return new WP_REST_Response(array('ok' => false, 'error' => 'bad date'), 400);
    $wk = strtolower(substr($day->format('l'), 0, 3));
    $hours = isset($cfg['hours'][$wk]) ? $cfg['hours'][$wk] : array();
    if ( count($hours) < 2 ) return new WP_REST_Response(array('ok' => true, 'date' => $date, 'slots' => array()), 200);
    global $wpdb; $t = fvc_bridge_booking_table();
    $booked = $wpdb->get_results($wpdb->prepare("SELECT start_local,end_local,practitioner FROM $t WHERE listing_id=%d AND status!='cancelled' AND DATE(start_local)=%s", $id, $date), ARRAY_A);
    $parts = explode(':', $hours[0]); $oh = (int) $parts[0]; $om = (int) ($parts[1] ?? 0);
    $parts = explode(':', $hours[1]); $ch = (int) $parts[0]; $cm = (int) ($parts[1] ?? 0);
    $cur = clone $day; $cur->setTime($oh, $om);
    $endw = clone $day; $endw->setTime($ch, $cm);
    $now = new DateTime('now', $tz);
    $slots = array(); $guard = 0;
    while ( $guard++ < 200 ) {
        $slotEnd = clone $cur; $slotEnd->modify('+' . $svcMin . ' minutes');
        if ( $slotEnd > $endw ) break;
        if ( $cur > $now ) {
            $s = $cur->format('Y-m-d H:i:s'); $e = $slotEnd->format('Y-m-d H:i:s'); $clash = false;
            foreach ( $booked as $bk ) {
                if ( $pract && $bk['practitioner'] !== $pract ) continue;
                if ( $s < $bk['end_local'] && $e > $bk['start_local'] ) { $clash = true; break; }
            }
            if ( ! $clash ) $slots[] = $cur->format('H:i');
        }
        $cur->modify('+' . $svcMin . ' minutes');
    }
    return new WP_REST_Response(array('ok' => true, 'date' => $date, 'slots' => $slots), 200);
}

function fvc_bridge_require_token_or_public($req) {
    $ip = fvc_bridge_ip(); $k = 'fvc_bk_rl_' . md5($ip); $n = (int) get_transient($k);
    if ( $n > 12 ) return new WP_Error('rate_limited', 'Too many requests', array('status' => 429));
    set_transient($k, $n + 1, MINUTE_IN_SECONDS);
    return true;
}

function fvc_bridge_booking_ics($appt, $cfg) {
    $tz = new DateTimeZone($cfg['timezone']);
    $start = DateTime::createFromFormat('Y-m-d H:i:s', $appt['start_local'], $tz);
    $end   = DateTime::createFromFormat('Y-m-d H:i:s', $appt['end_local'], $tz);
    $utc = new DateTimeZone('UTC');
    $start->setTimezone($utc); $end->setTimezone($utc);
    $stamp = gmdate('Ymd\THis\Z');
    $summary = ($appt['service'] ?: 'Appointment') . ' — ' . $cfg['clinic'];
    $desc = 'Booking at ' . $cfg['clinic'] . ($appt['practitioner'] ? (' with ' . $appt['practitioner']) : '');
    return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Find Vancouver Clinics//Booking//EN\r\nCALSCALE:GREGORIAN\r\nMETHOD:PUBLISH\r\n"
        . "BEGIN:VEVENT\r\nUID:fvc-" . $appt['id'] . "@findvancouverclinics.com\r\nDTSTAMP:$stamp\r\n"
        . "DTSTART:" . $start->format('Ymd\THis\Z') . "\r\nDTEND:" . $end->format('Ymd\THis\Z') . "\r\n"
        . "SUMMARY:" . addcslashes($summary, ",;\\") . "\r\nDESCRIPTION:" . addcslashes($desc, ",;\\") . "\r\n"
        . "STATUS:CONFIRMED\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
}

function fvc_bridge_rest_booking_create($req) {
    $b = $req->get_json_params(); $id = (int) ($b['listing_id'] ?? 0);
    $p = $id ? get_post($id) : null;
    if ( ! $p || $p->post_type !== 'gd_place' ) return new WP_REST_Response(array('ok' => false, 'error' => 'clinic not found'), 404);
    if ( empty($b['consent']) ) return new WP_REST_Response(array('ok' => false, 'error' => 'consent required'), 400);
    $cfg = fvc_bridge_booking_get_config($id);
    $name = sanitize_text_field($b['name'] ?? ''); $email = sanitize_email($b['email'] ?? ''); $phone = sanitize_text_field($b['phone'] ?? '');
    $svc = sanitize_text_field($b['service'] ?? ''); $pract = sanitize_text_field($b['practitioner'] ?? '');
    $date = preg_replace('/[^0-9\-]/', '', $b['date'] ?? ''); $time = preg_replace('/[^0-9:]/', '', $b['time'] ?? '');
    $notes = sanitize_textarea_field($b['notes'] ?? '');
    if ( ! $name || ! is_email($email) || ! $date || ! $time ) return new WP_REST_Response(array('ok' => false, 'error' => 'missing details'), 400);
    $dur = (int) $cfg['slotMinutes'];
    foreach ( $cfg['services'] as $s ) { if ( $s['name'] === $svc ) { $dur = (int) $s['duration']; break; } }
    if ( $dur < 15 ) $dur = 45;
    $tz = new DateTimeZone($cfg['timezone']);
    $start = DateTime::createFromFormat('Y-m-d H:i', $date . ' ' . $time, $tz);
    if ( ! $start ) return new WP_REST_Response(array('ok' => false, 'error' => 'bad time'), 400);
    $end = clone $start; $end->modify('+' . $dur . ' minutes');
    fvc_bridge_booking_ensure_table();
    global $wpdb; $t = fvc_bridge_booking_table();
    $s = $start->format('Y-m-d H:i:s'); $e = $end->format('Y-m-d H:i:s');
    if ( $pract ) {
        $clash = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $t WHERE listing_id=%d AND status!='cancelled' AND practitioner=%s AND %s<end_local AND %s>start_local", $id, $pract, $s, $e));
    } else {
        $clash = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $t WHERE listing_id=%d AND status!='cancelled' AND %s<end_local AND %s>start_local", $id, $s, $e));
    }
    if ( $clash > 0 ) return new WP_REST_Response(array('ok' => false, 'error' => 'That time was just taken — please pick another slot.'), 409);
    $key = wp_generate_password(24, false);
    $wpdb->insert($t, array(
        'listing_id' => $id, 'service' => $svc, 'practitioner' => $pract,
        'start_local' => $s, 'end_local' => $e, 'name' => $name, 'email' => $email, 'phone' => $phone,
        'notes' => $notes, 'status' => 'pending', 'manage_key' => $key, 'created_at' => current_time('mysql'),
    ));
    $appt = array('id' => (int) $wpdb->insert_id, 'service' => $svc, 'practitioner' => $pract, 'start_local' => $s, 'end_local' => $e);
    $cfg['clinic'] = html_entity_decode($p->post_title, ENT_QUOTES);
    $when = $start->format('l, F j') . ' at ' . $start->format('g:i a');
    $manageUrl = add_query_arg(array('appt' => $appt['id'], 'key' => $key), home_url('/booking-manage/'));
    // patient confirmation
    if ( function_exists('fvc_bridge_email_shell') ) {
        $inner = '<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:#3f3f46;">Thanks, ' . esc_html($name) . ' — your appointment request is in.</p>'
            . '<div style="background:#f7f7f7;border-left:3px solid #09BDB8;border-radius:8px;padding:14px 16px;font-size:14px;color:#3f3f46;">'
            . '<strong>' . esc_html($cfg['clinic']) . '</strong><br>' . esc_html($svc ?: 'Appointment') . ($pract ? ' with ' . esc_html($pract) : '') . '<br>' . esc_html($when) . '</div>'
            . '<p style="margin:16px 0 0;font-size:13px;color:#6b6b6e;">Need to change it? <a href="' . esc_url($manageUrl) . '" style="color:#0a8f8b;">Manage your booking</a>.</p>';
        $headers = array('Content-Type: text/html; charset=UTF-8', 'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>');
        wp_mail($email, 'Your appointment request — ' . $cfg['clinic'], fvc_bridge_email_shell('Your appointment request is in.', 'Appointment requested', $inner), $headers);
        // clinic notification (owner)
        $owner = get_userdata((int) $p->post_author);
        $clinicEmail = $owner && is_email($owner->user_email) ? $owner->user_email : get_option('admin_email');
        if ( is_email($clinicEmail) ) {
            $ci = '<p style="margin:0 0 14px;font-size:15px;color:#3f3f46;">New booking request for <strong>' . esc_html($cfg['clinic']) . '</strong>:</p>'
                . '<div style="background:#f7f7f7;border-radius:8px;padding:14px 16px;font-size:14px;color:#3f3f46;">'
                . esc_html($name) . ' &middot; ' . esc_html($email) . ($phone ? ' &middot; ' . esc_html($phone) : '') . '<br>'
                . esc_html($svc ?: 'Appointment') . ($pract ? ' with ' . esc_html($pract) : '') . '<br>' . esc_html($when)
                . ($notes ? '<br><em>' . esc_html($notes) . '</em>' : '') . '</div>';
            wp_mail($clinicEmail, 'New booking request — ' . $name, fvc_bridge_email_shell('New booking request.', 'New booking request', $ci), $headers);
        }
    }
    return new WP_REST_Response(array('ok' => true, 'id' => $appt['id'], 'when' => $when, 'manageUrl' => $manageUrl, 'icsUrl' => add_query_arg(array('appt' => $appt['id'], 'key' => $key), rest_url('fvc-bridge/v1/booking-ics'))), 200);
}

function fvc_bridge_rest_booking_list($req) {
    $id = (int) $req->get_param('listing');
    if ( ! $id || ! fvc_bridge_booking_owns($id) ) return new WP_REST_Response(array('ok' => false, 'error' => 'not allowed'), 403);
    global $wpdb; $t = fvc_bridge_booking_table();
    $rows = $wpdb->get_results($wpdb->prepare("SELECT id,service,practitioner,start_local,end_local,name,email,phone,status FROM $t WHERE listing_id=%d ORDER BY start_local DESC LIMIT 500", $id), ARRAY_A);
    $feedKey = get_post_meta($id, '_fvc_booking_feedkey', true);
    if ( ! $feedKey ) { $feedKey = wp_generate_password(20, false); update_post_meta($id, '_fvc_booking_feedkey', $feedKey); }
    $feedUrl = add_query_arg(array('listing' => $id, 'key' => $feedKey), rest_url('fvc-bridge/v1/booking-feed'));
    return new WP_REST_Response(array('ok' => true, 'appointments' => $rows ?: array(), 'clinic' => html_entity_decode(get_the_title($id), ENT_QUOTES), 'feedUrl' => $feedUrl), 200);
}
function fvc_bridge_rest_booking_status($req) {
    $b = $req->get_json_params(); $aid = (int) ($b['id'] ?? 0); $status = sanitize_text_field($b['status'] ?? '');
    if ( ! $aid || ! in_array($status, array('confirmed', 'cancelled', 'pending'), true) ) return new WP_REST_Response(array('ok' => false, 'error' => 'bad request'), 400);
    global $wpdb; $t = fvc_bridge_booking_table();
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $t WHERE id=%d", $aid), ARRAY_A);
    if ( ! $row ) return new WP_REST_Response(array('ok' => false, 'error' => 'not found'), 404);
    $key = sanitize_text_field($b['key'] ?? '');
    $allowed = fvc_bridge_booking_owns((int) $row['listing_id']) || ( $key && hash_equals($row['manage_key'], $key) && $status === 'cancelled' );
    if ( ! $allowed ) return new WP_REST_Response(array('ok' => false, 'error' => 'not allowed'), 403);
    $wpdb->update($t, array('status' => $status), array('id' => $aid));
    return new WP_REST_Response(array('ok' => true, 'status' => $status), 200);
}
function fvc_bridge_rest_booking_ics($req) {
    $aid = (int) $req->get_param('appt'); $key = sanitize_text_field((string) $req->get_param('key'));
    global $wpdb; $t = fvc_bridge_booking_table();
    $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $t WHERE id=%d", $aid), ARRAY_A);
    if ( ! $row || ! $key || ! hash_equals($row['manage_key'], $key) ) { status_header(404); echo 'Not found'; exit; }
    $cfg = fvc_bridge_booking_get_config((int) $row['listing_id']);
    $cfg['clinic'] = html_entity_decode(get_the_title((int) $row['listing_id']), ENT_QUOTES);
    nocache_headers();
    header('Content-Type: text/calendar; charset=utf-8');
    header('Content-Disposition: attachment; filename="appointment.ics"');
    echo fvc_bridge_booking_ics($row, $cfg);
    exit;
}
function fvc_bridge_rest_booking_feed($req) {
    $id = (int) $req->get_param('listing'); $key = sanitize_text_field((string) $req->get_param('key'));
    if ( ! $id ) { status_header(404); echo 'Not found'; exit; }
    $feedKey = get_post_meta($id, '_fvc_booking_feedkey', true);
    if ( ! $feedKey ) { $feedKey = wp_generate_password(20, false); update_post_meta($id, '_fvc_booking_feedkey', $feedKey); }
    if ( ! $key || ! hash_equals($feedKey, $key) ) { status_header(403); echo 'Forbidden'; exit; }
    $cfg = fvc_bridge_booking_get_config($id);
    $cfg['clinic'] = html_entity_decode(get_the_title($id), ENT_QUOTES);
    global $wpdb; $t = fvc_bridge_booking_table();
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM $t WHERE listing_id=%d AND status!='cancelled' AND start_local>=%s ORDER BY start_local ASC LIMIT 500", $id, gmdate('Y-m-d 00:00:00', time() - 86400)), ARRAY_A);
    nocache_headers();
    header('Content-Type: text/calendar; charset=utf-8');
    $out = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Find Vancouver Clinics//Booking//EN\r\nX-WR-CALNAME:" . addcslashes($cfg['clinic'] . ' bookings', ",;\\") . "\r\n";
    foreach ( (array) $rows as $r ) {
        $body = fvc_bridge_booking_ics($r, $cfg);
        if ( preg_match('/BEGIN:VEVENT.*END:VEVENT/s', $body, $m) ) $out .= $m[0] . "\r\n";
    }
    $out .= "END:VCALENDAR\r\n";
    echo $out; exit;
}

// ============================================================
//  Auto-generate a starter clinic site (Noir) on claim approval.
//  A compact server-side render so a site is LIVE the moment an owner
//  is approved; they then refine it in the full builder (/clinic-editor)
//  which republishes the richer version. Kept intentionally simple.
// ============================================================
function fvc_bridge_render_starter($listing_id) {
    global $wpdb;
    $p = get_post($listing_id);
    if ( ! $p ) return '';
    $d = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}geodir_gd_place_detail WHERE post_id=%d", $listing_id), ARRAY_A) ?: array();
    $yes = function ($v) { return $v === '1' || $v === 1 || $v === 'Yes'; };
    $name  = html_entity_decode($p->post_title, ENT_QUOTES);
    $short = trim(preg_split('/\s+/', $name)[0]);
    $hood  = $d['neighbourhood'] ?? ''; $city = $d['city'] ?? 'Vancouver';
    $loc   = $hood ? ($hood . ', ' . $city) : $city;
    $addr  = trim($d['street'] ?? ''); $phone = $d['l'] ?? ''; $phoneRaw = preg_replace('/\D/', '', $phone);
    $hours = $d['business_hours'] ?? 'Call for hours';
    $rating = isset($d['google_rating']) ? (float) $d['google_rating'] : 0;
    $reviews = isset($d['google_review_count']) ? (int) $d['google_review_count'] : 0;
    $cats = wp_get_post_terms($listing_id, 'gd_placecategory', array('fields' => 'names'));
    if ( ! $cats ) $cats = array('Appointment');
    $icbc = $yes($d['icbc_approved'] ?? ''); $db = $yes($d['direct_billing'] ?? ''); $ob = $yes($d['online_booking_available'] ?? '');
    $bookUrl = home_url('/book/?clinic=' . $listing_id);
    $e = 'esc_html'; $tel = 'tel:' . $phoneRaw;

    $DESC = array('Physiotherapy'=>'Hands-on and exercise-based care for injury, pain and recovery.','Chiropractic'=>'Adjustments and manual therapy to relieve pain and restore movement.','Massage Therapy'=>'Registered therapeutic massage to ease tension and speed recovery.','Acupuncture'=>'Traditional acupuncture to manage pain and support healing.','Naturopath'=>'Natural, whole-body care tailored to you.','Kinesiology'=>'Active rehab to rebuild strength and movement.');
    $svcCards = '';
    foreach ( $cats as $c ) { $svcCards .= '<div class="cs-card"><h3>' . $e($c) . '</h3><p>' . $e($DESC[$c] ?? ('Professional ' . strtolower($c) . ' care.')) . '</p></div>'; }
    $feats = array(); if ($icbc) $feats[] = 'ICBC approved'; if ($db) $feats[] = 'Direct billing'; if ($ob) $feats[] = 'Online booking'; $feats[] = ($hood ?: 'Vancouver') . ' location';
    $featPills = ''; foreach ($feats as $f) $featPills .= '<span class="cs-feat">' . $e($f) . '</span>';
    $stats = array(
        $rating > 0 ? array('&#9733; ' . number_format($rating, 1), 'Rated by ' . $reviews) : array('Trusted', 'Local clinic'),
        array((string) count($cats), 'Services in-house'),
        $db ? array('$0', 'With direct billing') : ($icbc ? array('ICBC', 'Approved') : array('Same-week', 'Appointments')),
        $ob ? array('Online', 'Booking available') : array($hood ?: 'Vancouver', 'Location'),
    );
    $statHtml = ''; foreach ($stats as $s) $statHtml .= '<div class="cs-stat"><div class="n">' . $s[0] . '</div><div class="l">' . $e($s[1]) . '</div></div>';
    $chip = $rating > 0 ? ('<span class="cs-chip"><b>&#9733; ' . number_format($rating, 1) . '</b> ' . $reviews . ' reviews &middot; ' . $e($loc) . '</span>') : ('<span class="cs-chip">' . $e($loc) . '</span>');
    $tagline = count($cats) > 1 ? ('Multidisciplinary care in ' . $e($loc) . ' &mdash; a full team under one roof.') : ($e($cats[0]) . ' in ' . $e($loc) . '.');

    $css = ".cs{background:#0a0a0b;color:#fff;font-family:'Plus Jakarta Sans',-apple-system,Segoe UI,Arial,sans-serif;line-height:1.6;}"
      . ".cs *{box-sizing:border-box;margin:0;}.cs img{max-width:100%;display:block;}.cs a{color:inherit;text-decoration:none;}"
      . ".cs-wrap{max-width:1080px;margin:0 auto;padding:0 22px;}"
      . ".cs-hdr{position:sticky;top:0;z-index:40;background:rgba(10,10,11,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid rgba(255,255,255,.1);}"
      . ".cs-hdr-in{max-width:1080px;margin:0 auto;padding:14px 22px;display:flex;align-items:center;justify-content:space-between;gap:16px;}"
      . ".cs-logo{font-weight:700;font-size:20px;letter-spacing:-.4px;}.cs-btn{display:inline-block;background:linear-gradient(135deg,#fff,#c9c9ce);color:#0a0a0b;padding:11px 22px;border-radius:999px;font-weight:600;font-size:14.5px;}"
      . ".cs-btn-ghost{background:transparent;color:#fff;border:1px solid rgba(255,255,255,.3);}"
      . ".cs-hero{padding:96px 22px 84px;text-align:left;background:radial-gradient(600px 300px at 15% 0%,rgba(255,255,255,.08),transparent 60%),#0a0a0b;}"
      . ".cs-hero-in{max-width:1080px;margin:0 auto;}.cs-chip{display:inline-flex;align-items:center;gap:8px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);padding:7px 14px;border-radius:999px;font-size:13px;font-weight:600;margin-bottom:20px;}.cs-chip b{color:#ffd24a;}"
      . ".cs-h1{font-size:clamp(34px,5.6vw,56px);font-weight:600;line-height:1.04;letter-spacing:-1.6px;max-width:16ch;}"
      . ".cs-tag{color:rgba(255,255,255,.78);font-size:clamp(16px,2vw,20px);margin-top:18px;max-width:54ch;}.cs-cta{display:flex;flex-wrap:wrap;gap:12px;margin-top:30px;}"
      . ".cs-trust{max-width:1080px;margin:-40px auto 0;padding:0 22px;position:relative;z-index:5;}.cs-trust-in{background:#151517;border:1px solid rgba(255,255,255,.1);border-radius:16px;display:grid;grid-template-columns:repeat(4,1fr);overflow:hidden;}"
      . ".cs-stat{padding:22px 20px;border-right:1px solid rgba(255,255,255,.1);}.cs-stat:last-child{border-right:0;}.cs-stat .n{font-size:26px;font-weight:600;background:linear-gradient(135deg,#fff,#c9c9ce);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;}.cs-stat .l{color:rgba(255,255,255,.6);font-size:13px;margin-top:4px;}"
      . ".cs-sec{padding:70px 0;border-top:1px solid rgba(255,255,255,.1);}.cs-kick{color:#fff;font-weight:600;font-size:12.5px;letter-spacing:1.6px;text-transform:uppercase;margin-bottom:12px;opacity:.7;}.cs-h2{font-size:clamp(26px,3.6vw,36px);font-weight:600;letter-spacing:-.8px;}"
      . ".cs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px;margin-top:32px;}.cs-card{background:#151517;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:24px;}.cs-card h3{font-size:18px;font-weight:600;margin-bottom:8px;}.cs-card p{color:rgba(255,255,255,.6);font-size:14px;}"
      . ".cs-feats{display:flex;flex-wrap:wrap;gap:10px;margin-top:30px;}.cs-feat{background:#151517;border:1px solid rgba(255,255,255,.1);border-radius:999px;padding:10px 16px;font-size:14px;font-weight:500;}.cs-feat:before{content:'\\2713 ';color:#fff;}"
      . ".cs-visit{display:grid;grid-template-columns:1fr;gap:18px;margin-top:30px;color:rgba(255,255,255,.8);font-size:16px;}.cs-visit b{color:#fff;}"
      . ".cs-final{margin:70px 0;padding:60px 28px;text-align:center;border-radius:22px;background:linear-gradient(160deg,#1a1a1d,#0c0c0d);border:1px solid rgba(255,255,255,.1);}.cs-final h2{font-size:clamp(26px,3.6vw,34px);font-weight:600;}.cs-final p{color:rgba(255,255,255,.68);margin-top:10px;}"
      . ".cs-foot{border-top:1px solid rgba(255,255,255,.1);padding:40px 0;color:rgba(255,255,255,.55);font-size:14px;}.cs-foot-in{max-width:1080px;margin:0 auto;padding:0 22px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;}"
      . "@media(max-width:760px){.cs-trust-in{grid-template-columns:1fr 1fr;}.cs-stat:nth-child(2){border-right:0;}.cs-stat:nth-child(1),.cs-stat:nth-child(2){border-bottom:1px solid rgba(255,255,255,.1);}}"
      . ".cs .cs-h1,.cs .cs-h2,.cs .cs-card h3,.cs .cs-final h2,.cs .cs-logo{color:#fff !important;}.cs .cs-h1{font-size:clamp(34px,5.6vw,56px) !important;line-height:1.04;}.cs .cs-h2{font-size:clamp(26px,3.6vw,36px) !important;}";

    $html = '<style>' . $css . '</style><div class="cs t-noir">'
      . '<header class="cs-hdr"><div class="cs-hdr-in"><a class="cs-logo" href="#top"><b>' . $e($short) . '</b></a><a class="cs-btn" href="' . esc_url($bookUrl) . '">Book now</a></div></header>'
      . '<section class="cs-hero" id="top"><div class="cs-hero-in">' . $chip . '<h1 class="cs-h1">' . $e($name) . '</h1><p class="cs-tag">' . $tagline . '</p>'
      . '<div class="cs-cta"><a class="cs-btn" href="' . esc_url($bookUrl) . '">Book now</a>' . ($phoneRaw ? '<a class="cs-btn cs-btn-ghost" href="' . $tel . '">Call ' . $e($phone) . '</a>' : '') . '</div></div></section>'
      . '<div class="cs-trust"><div class="cs-trust-in">' . $statHtml . '</div></div>'
      . '<div class="cs-wrap">'
      . '<section class="cs-sec"><p class="cs-kick">Services</p><h2 class="cs-h2">What we offer</h2><div class="cs-grid">' . $svcCards . '</div></section>'
      . '<section class="cs-sec"><p class="cs-kick">Why patients choose us</p><h2 class="cs-h2">Care made simple</h2><div class="cs-feats">' . $featPills . '</div></section>'
      . '<section class="cs-sec"><p class="cs-kick">Visit</p><h2 class="cs-h2">Come see us</h2><div class="cs-visit">' . ($addr ? '<div><b>Address</b><br>' . $e($addr) . '</div>' : '') . ($phone ? '<div><b>Phone</b><br><a href="' . $tel . '">' . $e($phone) . '</a></div>' : '') . '<div><b>Hours</b><br>' . $e($hours) . '</div></div></section>'
      . '<div class="cs-final"><h2>Ready to feel better?</h2><p>' . ($icbc ? 'ICBC approved &middot; ' : '') . ($db ? 'Direct billing &middot; ' : '') . 'Book online today</p><div class="cs-cta" style="justify-content:center;margin-top:24px;"><a class="cs-btn" href="' . esc_url($bookUrl) . '">Book now</a></div></div>'
      . '</div><footer class="cs-foot"><div class="cs-foot-in"><span><b style="color:#fff;">' . $e($name) . '</b>' . ($addr ? ' &middot; ' . $e($addr) : '') . '</span><span>Built with <a style="color:rgba(255,255,255,.75);" href="' . home_url('/') . '">Find Vancouver Clinics</a></span></div></footer>'
      . '</div>';
    return $html;
}

// Create/update the clinic's white-label site page from the starter render. Returns [site_id, url] or WP_Error.
function fvc_bridge_generate_site($listing_id, $author = 0) {
    $listing = get_post($listing_id);
    if ( ! $listing || $listing->post_type !== 'gd_place' ) return new WP_Error('nolisting', 'listing not found');
    $html = fvc_bridge_render_starter($listing_id);
    if ( strlen($html) < 50 ) return new WP_Error('empty', 'render failed');
    $site_id = (int) get_post_meta($listing_id, '_fvc_site_page', true);
    if ( $site_id && ! get_post($site_id) ) $site_id = 0;
    $title = html_entity_decode($listing->post_title, ENT_QUOTES);
    if ( ! $author ) $author = (int) $listing->post_author ?: 1;
    kses_remove_filters();
    if ( $site_id ) {
        $r = wp_update_post(array('ID' => $site_id, 'post_content' => wp_slash($html), 'post_title' => $title), true);
    } else {
        $r = wp_insert_post(array('post_type' => 'page', 'post_status' => 'publish', 'post_title' => $title,
            'post_name' => sanitize_title($title), 'post_content' => wp_slash($html), 'post_author' => $author), true);
    }
    kses_init_filters();
    if ( is_wp_error($r) ) return $r;
    if ( ! $site_id ) $site_id = (int) $r;
    update_post_meta($site_id, '_fvc_raw_html', 1);
    update_post_meta($site_id, '_wp_page_template', 'elementor_canvas');
    update_post_meta($site_id, '_fvc_site_listing', $listing_id);
    update_post_meta($listing_id, '_fvc_site_page', $site_id);
    if ( function_exists('fvc_bridge_indexnow_ping') ) fvc_bridge_indexnow_ping(get_permalink($site_id));
    return array($site_id, get_permalink($site_id));
}

// Token/owner endpoint to generate (or regenerate) a starter site — also used for testing.
function fvc_bridge_rest_clinic_generate($req) {
    $b = $req->get_json_params(); $id = (int) ($b['listing_id'] ?? 0);
    if ( ! $id ) return new WP_REST_Response(array('ok' => false, 'error' => 'listing_id required'), 400);
    if ( ! fvc_bridge_booking_owns($id) ) return new WP_REST_Response(array('ok' => false, 'error' => 'not allowed'), 403);
    $res = fvc_bridge_generate_site($id, get_current_user_id());
    if ( is_wp_error($res) ) return new WP_REST_Response(array('ok' => false, 'error' => $res->get_error_message()), 500);
    return new WP_REST_Response(array('ok' => true, 'post_id' => $res[0], 'view' => $res[1]), 200);
}
