<?php
/*
Plugin Name: Gravity Forms: Magic Link
Plugin URI: https://github.com/codearachnid/gform-magic-link/
Description: Gravity Forms Magic Link functionality allows you to send a magic link to a registered email for an automatic login
Author: Timothy Wood (@codearachnid)
Version: 1.0.0
Requires at least: 6.0
Requires PHP: 7.3
Tested up to: 6.1.1
Author URI: https://codearachnid.com
License: GPL-3.0+
License URI: https://www.gnu.org/licenses/gpl-3.0.html
Text Domain: gform_magic_link
*/

/*
	Copyright 2022 Timothy Wood

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// Exit if accessed directly
if (!defined('ABSPATH') )
    exit;

/**
 *
 * !ATTN devs There are several hooks to allow you to customize the functionality more directly
 *
 **/

add_filter('gform_notification', 'gform_add_magic_link_to_notification', 10, 3);
function gform_add_magic_link_to_notification( $notification, $form, $entry ) {

	// filter by form id or use gform_notification_{form_id}
	$form_id = apply_filters( 'gform_magic_link_notification_form_id', 'all' );
	if( $form_id != 'all' || ( is_array($form_id) && !in_array( $form->id, $form_id ) ) || ( !empty($form_id) && $form_id != $form->id ) ){
		return $notification;
	}

	$user_email = '';
	
    // Loop through the form fields to find the one with the "magic_link" key
    foreach ($form['fields'] as $field) {
        if (isset($field->allowsPrepopulate) && $field->allowsPrepopulate && $field->inputName === 'magic_link') {
            // Get the email from the entry based on the field ID
            $user_email = rgar( $entry, strval( $field->id ) );
            break;
        }
    }
	
	$user = get_user_by( 'email', sanitize_email( $user_email ) );
	
	// no user found - prevent notification from sending
	if (!$user) {
        $notification = false;
        return $notification;
    }

	$token = gform_magic_link_generate_secure_token($user_id);
    $expiry = time() + 15 * MINUTE_IN_SECONDS; // Set expiry time to 15 minutes

    // Store the token and expiry time as user meta
    update_user_meta( $user->ID, '_magic_link_token', $token );
    update_user_meta( $user->ID, '_magic_link_token_expiry', $expiry );

    // Create the magic link
    $magic_link = add_query_arg( [
        'action' => 'magic_link',
        'email' => $user->user_email,
        'token' => $token,
    ], home_url() );
	
    // Replace a placeholder in the notification message with the magic link
    $notification['message'] = str_replace('{magic_link}', esc_url($magic_link), $notification['message']);
	
    return $notification;
}



add_action( 'admin_post_nopriv_magic_link', 'gform_handle_magic_link_login' );
add_action( 'admin_post_magic_link', 'gform_handle_magic_link_login' );
add_action( 'template_redirect', 'gform_handle_magic_link_login' );
function gform_handle_magic_link_login() {
	
	// confirm action is magic_link before proceeding
	if( !isset($_GET['action']) || $_GET['action'] != 'magic_link' ){
		return;
	}
	
	// does not have the correct parameters to be a magic link
	if (!isset($_GET['email']) || !isset($_GET['token']) ) {
        wp_die('Invalid magic link.');
    }
	
    $email = urldecode( $_GET['email'] );
    $token = sanitize_text_field( $_GET['token'] );
	$user = get_user_by( 'email', sanitize_email( $email ) );
	
	// no user found
	if (!$user) {
		wp_die( 'This magic link is invalid.' );
    }

    $stored_token = get_user_meta( $user->ID, '_magic_link_token', true );
    $expiry = get_user_meta( $user->ID, '_magic_link_token_expiry', true );

	// token is invalid
    if ( $token !== $stored_token || time() > $expiry ) {
        wp_die( 'This magic link is invalid or has expired.' );
    }

    // Log the user in
    wp_set_auth_cookie( $user->ID );
    delete_user_meta( $user->ID, '_magic_link_token' );
    delete_user_meta( $user->ID, '_magic_link_token_expiry' );

    // Redirect to the desired page after login
    wp_redirect( apply_filters( 'gform_handle_magic_link_login_redirect', home_url() ) );
    exit;
}

if( !function_exists('gform_magic_link_generate_secure_token') ){
  function gform_magic_link_generate_secure_token($user_id) {
    $random_bytes = random_bytes(32);
    $site_salt = defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : bin2hex( $random_bytes );
    $user_salt = hash( 'sha256', $user_id . $site_salt );
    $token = hash_hmac('sha256', $random_bytes, $user_salt);
    return apply_filters( 'gform_magic_link_generate_secure_token', $token );
  }
}
