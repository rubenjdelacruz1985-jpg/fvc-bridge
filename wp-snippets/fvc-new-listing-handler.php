<?php
/**
 * FVC New Listing — AJAX handler  (Code Snippets id ~1071)
 *
 * Cleaned:
 *   - Brevo key from wp-config constant FVC_BREVO_API_KEY (no hardcoded secret).
 *   - CASL: only add to the Brevo marketing list with explicit consent
 *     ($_POST['marketing_consent']). Everyone still gets the transactional emails.
 *   - Improved, branded confirmation email (shares fvc_email_shell with the claim handler).
 *   - Submission capture/dedup handled automatically by the FVC Bridge plugin.
 *
 * When pasting into Code Snippets, omit the opening "<?php" line and this header.
 */

add_action('wp_ajax_fvc_new_listing',        'fvc_handle_new_listing');
add_action('wp_ajax_nopriv_fvc_new_listing', 'fvc_handle_new_listing');

function fvc_handle_new_listing() {
    if ( ! isset($_POST['nonce']) || ! wp_verify_nonce($_POST['nonce'], 'fvc_claim_nonce') ) {
        wp_send_json_error('Invalid request');
        exit;
    }

    $clinic_name    = sanitize_text_field($_POST['clinic_name']    ?? '');
    $clinic_website = esc_url_raw($_POST['clinic_website']         ?? '');
    $clinic_address = sanitize_text_field($_POST['clinic_address'] ?? '');
    $contact_name   = sanitize_text_field($_POST['contact_name']   ?? '');
    $role           = sanitize_text_field($_POST['role']           ?? '');
    $email          = sanitize_email($_POST['email']               ?? '');
    $phone          = sanitize_text_field($_POST['phone']          ?? '');
    $services       = sanitize_text_field($_POST['services']       ?? 'Not specified');
    $icbc           = sanitize_text_field($_POST['icbc']           ?? 'Not answered');
    $worksafe       = sanitize_text_field($_POST['worksafe']       ?? 'Not answered');
    $billing        = sanitize_text_field($_POST['billing']        ?? 'Not answered');
    $booking        = sanitize_text_field($_POST['booking']        ?? 'Not answered');
    $notes          = sanitize_textarea_field($_POST['notes']      ?? '');
    $consent        = ! empty($_POST['marketing_consent']);

    if ( ! $clinic_name || ! $email || ! $contact_name ) {
        wp_send_json_error('Missing required fields');
        exit;
    }

    // ── Admin notification ────────────────────────────────────
    $subject = 'New Listing Request: ' . $clinic_name;
    $body = '
    <html><body style="font-family: sans-serif; color: #1a1a1a; max-width: 600px; margin: 0 auto;">
    <div style="background: #09BDB8; padding: 24px 32px; border-radius: 8px 8px 0 0;">
        <h2 style="color: #fff; margin: 0; font-size: 20px;">New Listing Request</h2>
        <p style="color: rgba(255,255,255,0.8); margin: 4px 0 0; font-size: 14px;">Find Vancouver Clinics</p>
    </div>
    <div style="background: #f7f7f7; padding: 32px; border-radius: 0 0 8px 8px;">
        <table style="width:100%; border-collapse: collapse; margin-bottom: 24px;">
            <tr><td style="padding: 8px 0; color: #666; width: 40%;">Clinic name</td><td style="padding: 8px 0; font-weight: 500;">' . esc_html($clinic_name) . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Website</td><td style="padding: 8px 0;">' . ($clinic_website ? '<a href="' . esc_url($clinic_website) . '">' . esc_html($clinic_website) . '</a>' : '—') . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Address</td><td style="padding: 8px 0;">' . esc_html($clinic_address ?: '—') . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Contact</td><td style="padding: 8px 0;">' . esc_html($contact_name) . ' (' . esc_html($role) . ')</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Email</td><td style="padding: 8px 0;"><a href="mailto:' . esc_attr($email) . '">' . esc_html($email) . '</a></td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Phone</td><td style="padding: 8px 0;">' . esc_html($phone) . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Services</td><td style="padding: 8px 0;">' . esc_html($services) . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">ICBC / WSBC</td><td style="padding: 8px 0;">' . esc_html($icbc) . ' / ' . esc_html($worksafe) . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Billing / Booking</td><td style="padding: 8px 0;">' . esc_html($billing) . ' / ' . esc_html($booking) . '</td></tr>
            <tr><td style="padding: 8px 0; color: #666;">Marketing consent</td><td style="padding: 8px 0;">' . ($consent ? 'Yes' : 'No') . '</td></tr>
        </table>
        ' . ($notes ? '<p style="background:#fff;padding:16px;border-radius:6px;border-left:3px solid #09BDB8;margin:0;">' . esc_html($notes) . '</p>' : '') . '
    </div>
    </body></html>';

    $headers = array(
        'Content-Type: text/html; charset=UTF-8',
        'From: Find Vancouver Clinics <noreply@findvancouverclinics.com>',
        'Reply-To: ' . esc_html($contact_name) . ' <' . sanitize_email($email) . '>',
    );
    $sent = wp_mail('claim@findvancouverclinics.com', $subject, $body, $headers);

    // ── Confirmation to the submitter (branded) ───────────────
    $reply_subject = 'We received your listing request — Find Vancouver Clinics';
    $reply_body = fvc_email_shell(
        'Your clinic is in our review queue — live within 48 hours.',
        'Thanks, ' . esc_html($contact_name) . ' — we\'ve got it.',
        '<p style="margin:0 0 18px;font-size:15px;line-height:1.6;color:#3f3f46;">We received your submission for <strong>' . esc_html($clinic_name) . '</strong>. It\'s now in our review queue.</p>'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:8px 0 24px;">'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">1.</span>&nbsp; We review your details for accuracy.</td></tr>'
        . '<tr><td style="padding:10px 0;border-bottom:1px solid #eee;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">2.</span>&nbsp; Your clinic goes live — usually within <strong>48 hours</strong>.</td></tr>'
        . '<tr><td style="padding:10px 0;font-size:14px;color:#3f3f46;"><span style="color:#09BDB8;font-weight:700;">3.</span>&nbsp; We email you the link the moment it\'s published.</td></tr>'
        . '</table>'
        . '<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 8px;"><tr><td style="border-radius:8px;background:#09BDB8;"><a href="https://findvancouverclinics.com/places/" style="display:inline-block;padding:12px 22px;font-size:15px;font-weight:600;color:#fff;text-decoration:none;">Browse the directory →</a></td></tr></table>'
        . '<p style="margin:14px 0 0;font-size:14px;line-height:1.6;color:#3f3f46;">It\'s completely free to be listed — no payment, ever, for a basic listing.</p>'
    );
    wp_mail($email, $reply_subject, $reply_body, $headers);

    // ── Brevo — ONLY with explicit marketing consent (CASL) ───
    $brevo_api_key = defined('FVC_BREVO_API_KEY') ? FVC_BREVO_API_KEY : '';
    if ( $brevo_api_key && $consent ) {
        $name_parts = explode(' ', $contact_name, 2);
        wp_remote_post('https://api.brevo.com/v3/contacts', array(
            'headers' => array('accept' => 'application/json', 'content-type' => 'application/json', 'api-key' => $brevo_api_key),
            'body' => json_encode(array(
                'email'         => $email,
                'listIds'       => array(4),
                'updateEnabled' => true,
                'attributes'    => array(
                    'FIRSTNAME'         => $name_parts[0],
                    'LASTNAME'          => isset($name_parts[1]) ? $name_parts[1] : '',
                    'CLINIC_NAME'       => $clinic_name,
                    'ROLE'              => $role,
                    'CLAIM_STATUS'      => 'new_listing',
                    'SERVICES'          => $services,
                    'ICBC_APPROVED'     => $icbc,
                    'WORKSAFE_APPROVED' => $worksafe,
                    'DIRECT_BILLING'    => $billing,
                    'ONLINE_BOOKING'    => $booking,
                ),
            )),
            'timeout' => 15,
        ));
    }

    if ($sent) {
        wp_send_json_success('Listing request submitted');
    } else {
        wp_send_json_error('Mail failed');
    }
    exit;
}

// Shared branded email shell (define once; safe if both handlers include it).
if ( ! function_exists('fvc_email_shell') ) {
    function fvc_email_shell($preheader, $heading, $inner_html) {
        return '<div style="display:none;max-height:0;overflow:hidden;opacity:0;">' . esc_html($preheader) . '</div>'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;font-family:Segoe UI,Helvetica,Arial,sans-serif;"><tr><td align="center">'
        . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#fff;border-radius:12px;overflow:hidden;">'
        . '<tr><td style="background:#09090B;padding:26px 32px;"><span style="color:#fff;font-size:20px;font-weight:700;">Find Vancouver Clinics</span><span style="color:#09BDB8;font-size:20px;font-weight:700;"> ✓</span></td></tr>'
        . '<tr><td style="height:4px;background:#09BDB8;font-size:0;line-height:0;">&nbsp;</td></tr>'
        . '<tr><td style="padding:34px 32px 8px;"><h1 style="margin:0 0 14px;font-size:23px;line-height:1.25;color:#09090B;">' . $heading . '</h1>' . $inner_html
        . '<p style="margin:14px 0 0;font-size:14px;color:#6b6b6e;">— The Find Vancouver Clinics team</p></td></tr>'
        . '<tr><td style="padding:22px 32px;background:#fafafa;border-top:1px solid #eee;"><p style="margin:0;font-size:12px;line-height:1.5;color:#9ca3af;">Find Vancouver Clinics · Vancouver, BC<br>You received this because you contacted us at <a href="https://findvancouverclinics.com" style="color:#6b6b6e;">findvancouverclinics.com</a>.</p></td></tr>'
        . '</table></td></tr></table>';
    }
}
