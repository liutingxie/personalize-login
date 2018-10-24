<?php
/**
 * Plugin Name: Personlize Login
 * Descrition: A plugin that replaces the wordpress login flow with the 	custom page.
 * Author: storm
 * Version: 1.0
 * License: GPL -2.0+
 */
class  Personalize_Login_Plugin {


	/**
	 * initializes the plugin
	 * to keep the initializes fast, only add the adtion and filter
	 * hooks  in the constructor
	 */
	public function __construct() {
		//add shortcode create login page form
		add_shortcode( 'custom-login-form', array( $this, 'render_login_form' ) );

		add_shortcode( 'custom-register-form', array( $this, 'render_register_form' ) );

		add_shortcode( 'custom-password-lost-form', array( $this, 'render_password_lost_form' ) );

		add_shortcode( 'custom-password-reset-form', array( $this, 'render_password_reset_form' ) );

		add_action( 'login_form_login', array( $this, 'redirect_to_custom_login' ) );

		add_action( 'login_form_register', array( $this, 'redirect_to_custom_register' ) );

		add_action( 'login_form_lostpassword', array( $this, 'redirect_to_custom_lostpassword' ) );

		add_action( 'login_form_rp', array( $this, 'redirect_to_custom_password_reset' ) );

		add_action( 'login_form_resetpass', array( $this, 'redirect_to_custom_password_reset' ) );

		add_action( 'login_form_register', array( $this, 'do_register_user') );

		add_action( 'login_form_lostpassword', array( $this, 'do_password_lost') );

		// add_action( 'login_form_rp', array( $this, 'do_password_reset' ) );

		// add_action( 'login_form_resetpass', array( $this, 'do_password_reset') );

		add_filter( 'logout_redirect', array( $this, 'redirect_after_logout'), 10, 3 );

		add_action( 'wp_print_footer_scripts', array( $this, 'add_captcha_js_to_footer' ) );

		add_filter('authenticate', array( $this, 'maybe_redirect_at_authenticate'), 101, 3);

		add_filter( 'login_redirect', array( $this, 'redirect_after_login'), 10, 3 );

		add_filter( 'admin_init', array( $this, 'register_settings_field' ) );

		add_filter( 'retrieve_password_message', array( $this, 'replace_retrieve_password_message' ), 10, 4);
	}

	/**
	 * Plugin activation hook
	 * Create all wordpress page needed by the plugin
	 */
	public static function plugin_activeted()
	{
		// Information needed for creating the plugin page's
		$page_definitions = array(
				'member-login' => array(
					'title' => __('Sign In', 'storm-login'),
					'content' => '[custom-login-form]'
				),
				'member-account' => array(
					'title' => __('Your account', 'storm-login'),
					'content' => '[account-info]'
				),
				'member-register' => array(
					'title' => __('Register', 'storm_login'),
					'content' => '[custom-register-form]'
				),
				'member-password-lost' => array(
					'title' => __('Forgot You Password?', 'storm_login'),
					'content' => '[custom-password-lost-form]'
				),
				'member-password-reset' => array(
					'title' => __('Pick a New Pickassword.', 'storm_login'),
					'content' => '[custom-password-reset-form]'
				)
			);

		foreach ($page_definitions as $slug => $page)
		{
			//Check the page doesn't exist alreadly
			$query = new WP_Query( 'pagename=' . $slug);

			if( ! $query->have_posts() )
			{
				//add the page using the data from the array above
			        wp_insert_post( array(
						'post_content' => $page['content'],
						'post_name' => $slug,
						'post_title' => $page['title'],
						'post_type' => 'page',
						'post_status' => 'publish',
						'ping_status' => 'closed',
						'comment_closed' => 'closed'
					) );
			}
		}
	}

	public static function plugin_deactiveted()
	{

		$page_title = array('Sign In','Your account','Register','Forgot You Password?','Pick a New Pickassword.');

		foreach( $page_title as $title )
		{
			$query = new WP_Query( $title );

			if( $query->have_posts() )
			{
				// other way to get page id
				// global $wpdb;
				// $page_id = $wpdb->get_var("SELECT ID FROM $wpdb->posts WHERE post_title = '".$title."'");
				// wp_delete_post( $page_id, true );


				$page_id = get_page_by_title( $title );
				wp_delete_post( $page_id->ID, true );
			}
		}
	}

	/**
	 * A shortcode for the rendeing login form
	 * @param  [array] $attributes shrotcode attributes
	 * @param  [string] $content   The text content for the shortcode, Not used
 	 * @return [string]             return login form output
	 */
	public function render_login_form( $attributes, $content = null)
	{
		//Parse shortcode attributes
		$defualt_attributes = array('show_title' => false);
		$attributes = shortcode_atts( $defualt_attributes, $attributes );
		$show_title = $attributes['show_title'];

		if( is_user_logged_in() )
		{
			return __('Your are alreadly signed in.', 'storm_login');
		}

		//Error messages
		$attributes['errors'] = array();
		if( isset($_REQUEST['login']) )
		{
			$error_codes = explode(',', $_REQUEST['login']);

			foreach ($error_codes as $error_code)
			{
				$attributes['errors'][] = $this->get_error_message($error_code);
			}
		}

		// Check if user just logged out
		$attributes['logged_out'] = isset($_REQUEST['logged_out']) && $_REQUEST['logged_out'] == 'true' ;



		//Check if the user just register
		$attributes['registered'] = isset( $_REQUEST['registered'] );

		// Check if the user just requested a new password
		$attributes['lost_password_sent'] = isset( $_REQUEST['checkmail'] ) && $_REQUEST['checkmail'] == 'confirm';

		// Check if user just updated password
		$attributes['password_updated'] = isset( $_REQUEST['password'] ) && $_REQUEST['password'] == 'changed';

		//Pass the redirect parameter to the wordpress functionality: by default, don't specify a redirect, but if a valid redirect Url has been passed as request parameter.use it
		$attributes['redirect'] = '';
		if( isset( $_REQUEST['redirect_to']) )
		{
			$attributes['redirect'] = wp_validate_redirect( $_REQUEST['redirect_to'], $attributes['redirect'] );
		}

		//Render the login form using an externel template
		return $this->get_html_template( 'login_form', $attributes );
	}

	/**
	 * Renders the contens  of the given template to string an return it
	 * @param  [type] $template_name [description]
	 * @param  [type] $attributes    [description]
	 * @return [type]                [description]
	 */
	private function get_html_template( $template_name, $attributes = null )
	{
		if( !$attributes )
		{
			$attributes = array();
		}
		ob_start();


		require( 'template/' . $template_name . '.php' );


		$html = ob_get_contents();

		ob_end_clean();

		return $html;
	}

	/**
	 * Redirect the user to the custom login page instead of wp-login.php
	 */
	function redirect_to_custom_login()
	{
		if( $_SERVER['REQUEST_METHOD'] === 'GET' )
		{
			$redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : null;

			if( is_user_logged_in() )
			{
				$this->redirect_logged_in_user($redirect_to);

				exit;
			}

			$user = wp_get_current_user();



			//The rest are redirected to the login page
			$login_url = home_url('member-login');

			if( !empty($redirect_to) )
			{
				$login_url = add_query_arg('redirect_to', $redirect_to, $login_url);
			}

			wp_redirect($login_url);

			exit;
		}
	}
	/**
	 * Redirects the user to currect page depending whether on he or she is an admin or not
	 * @param  [string] $redirect_to  An option redirect_to URL for admin users
	 */
	private function redirect_logged_in_user( $redirect_to = null )
	{
		$user = wp_get_current_user();
		if( user_can( $user, 'manager_options') )
		{
			if($redirect_to)
			{
				wp_safe_redirect( $redirect_to );
			}
			else
			{
				wp_redirect( admin_url() );
			}
		}
		else
		{
			wp_redirect( home_url( 'member-account' ) );
		}
	}

	/**
	 * Redirect the user after authentication if there were any errors
	 * @param  [string] $user     The signed in user, or the error that have occurred
	 * @param  [string] $username the user name used to log in
	 * @param  [string] $password the user password used to  log in
	 * @return [string]           The logged in user, or error imformation if there were errors
	 */
	function maybe_redirect_at_authenticate( $user, $username, $password )
	{	if( $_SERVER['REQUEST_METHOD'] === 'POST' )
		{
			if( is_wp_error($user) )
			{
				$error_codes = join( ',', $user->get_error_codes() );
				$login_url = home_url( 'member-login' );

				$login_url = add_query_arg('login', $error_codes, $login_url);

				wp_redirect($login_url);

				exit;
			}
		}

		return $user;
	}

	/**
	 * Find and returns a matching error message for given the error code
	 * @param  [type] $error_code [description]
	 * @return [type]             [description]
	 */
	private function get_error_message( $error_code )
	{
		switch ( $error_code ) {
		        case 'empty_username':
		            return __( 'You do have an email address, right?', 'storm_login' );

		        case 'empty_password':
		            return __( 'You need to enter a password to login.', 'storm_login' );

		        case 'invalid_username':
		            return __(
		                "We don't have any users with that email address. Maybe you used a different one when signing up?",
		                'storm_login'
		            );

		        case 'incorrect_password':
		            $err = __(
		                "The password you entered wasn't quite right. <a href='%s'>Did you forget your password</a>?",
		                'storm_login'
		            );
		            return sprintf( $err, wp_lostpassword_url() );

		 	//Register error
		 	case 'email':
		 		return __( 'The email address you entered is not valid.', 'storm_login' );

		 	case 'email_exists':
		 		return __(  'An account exists with this email address.', 'storm_login' );

		 	case 'closed':
		 		return __( 'Registering new users is currently not allowed.', 'storm_login' );

		 	case 'captcha':
    				return __( 'The Google reCAPTCHA check failed. Are you a robot?', 'storm_login' );

    			// Lost password

			case 'empty_username':
			    return __( 'You need to enter your email address to continue.', 'storm_login' );
			case 'invalid_email':

			case 'invalidcombo':
    				return __( 'There are no users registered with this email address.', 'storm_login' );

    			// Reset password

			case 'expiredkey':
			case 'invalidkey':
			    return __( 'The password reset link you used is not valid anymore.', 'storm_login' );

			case 'password_reset_mismatch':
			    return __( "The two passwords you entered don't match.", 'storm_login' );

			case 'password_reset_empty':
			    return __( "Sorry, we don't accept empty passwords.", 'storm_login' );

		        default:
		            break;
		    }

		return __( 'An unknown error occurred. Please try again later.', 'storm_login' );
	}

	function redirect_after_logout( $redirect_to, $requested_redirect_to, $user )
	{
		// wp_destroy_current_session();
		// wp_clear_auth_cookie();

		// $redirect_url = home_url( 'member-login?logged_out=true' );
		// wp_safe_redirect( $redirect_url );
		// exit;
		$redirect_to = home_url( 'member-login?logged_out=true' );
		return $redirect_to;
	}

	/**
	 * Returns the URL to which user should be redirect after the successful the login
	 * @param  [tring] $redirect_to         The redirect destination URL.
	 * @param  [string] $request_redirect_to The request redirect destination url passed as parameter
	 * @param  WP_USER | WP_ERROR $user     WP_ERROR object if login was successful, WP_ERROR object otherwite
	 * @return Redirect URL
	 */
	function redirect_after_login( $redirect_to, $request_redirect_to, $user)
	{
		$redirect_url = home_url();

		if( !isset($user->ID) )
		{
			return $redirect_url;
		}

		if( user_can( $user, 'manager_options') )
		{
			if($request_redirect_to = '')
			{
				$redirect_url = $admin_url();
			}
			else
			{
				$redirect_url = $request_redirect_to;
			}
		}
		else
		{
			$redirect_url = home_url('member-account');
		}

		return wp_validate_redirect($redirect_url, home_url());
	}

	/**
	 * A shortcode for render the new user register form
	 * @param  [array] $attributes The shortcode attributes
	 * @param  [string] $content    The text content for shortcode , Not used
	 * @return string The shortcode output
	 */
	public function render_register_form($attributes, $content = null)
	{
		//Parse shortcode attributes
		$defualt_attributes = array('show_title' => false);
		$attributes = shortcode_atts( $defualt_attributes, $attributes );

		$attributes['errors'] = array();
		if( isset($_REQUEST['register-errors']) )
		{
			$error_codes = explode(',', $_REQUEST['register-errors']);

			foreach ($error_codes as $error_code)
			{
				$attributes['errors'][] = $this->get_error_message($error_code);
			}
		}

		$attributes['recaptcha_site_key'] = get_option('personalize-login-recaptcha-site-key', null);

		if( is_user_logged_in() )
		{
			return __( 'You are alreadly signed in.', 'storm_login' );
		}
		else if ( !get_option('users_can_register') )
		{
			return __( 'Registering new users is currently not allowed', 'storm_login');
		}
		else
		{

			return $this->get_html_template( 'register_form', $attributes );
		}
	}

	/**
	 * Redirects the user custom registration page instead of wp-login.php?action=register
	 * @return [type] [description]
	 */
	public function redirect_to_custom_register()
	{
		if( $_SERVER['REQUEST_METHOD'] == "GET" )
		{
			if( is_user_logged_in() )
			{
				$this->redirect_logged_in_user();
			}
			else
			{
				wp_redirect( home_url('member-register') );
			}

			exit;
		}
	}

	/**
	 * Validates and then completes the new user signup process, if all t
	 *went well
	 * @param  [string] $email      The new user's email address
	 * @param  [string] $first_name The new uesr's first name
	 * @param  [string] $last_name  The new user's last name
	 * @return [string]        The id of the user's that was created, or error if failed
	 */
	private function register_user( $email, $first_name, $last_name )
	{
		$errors = new WP_Error();

		if( !is_email($email) )
		{
			$errors->add('email', $this->get_error_message('email') );
			return $errors;
		}

		if(username_exists( $email ) || email_exists( $email ) )
		{
			$errors->add('email_exists', $this->get_error_message('email_exists') );
			return $errors;
		}

		//Generate the password so that the subscriber will have check email
		$password = wp_generate_password( 12, false );

		$user_data = array(
			'user_login' => $email,
			'user_email' => $email,
			'user_pass' => $password,
			'first_name' => $first_name,
			'last_name' => $last_name,
			'nickname'      => $first_name
		);

		$user_id = wp_insert_user( $user_data );

		wp_new_user_notification($user_id, $password);

		return $user_id;
	}

	/**
	 * Handles the register of a new user
	 * Used through the action hook "login_form_register" activated on wp-login.php when accessed through the registration action.
	 */
	public function do_register_user( )
	{
		if( $_SERVER['REQUEST_METHOD'] == "POST" )
		{
			$redirect_url = home_url('member-register');

			if( !get_option('users_can_register') )
			{
				//Register closed, display error
				$redirect_url = add_query_arg( 'register-errors', 'closed', $redirect_url);
			}
			else if( !$this->verify_recaptcha() )
			{
				// Recaptcha check failed, display error
				$redirect_url = add_query_arg( 'register-errors', 'captcha', $redirect_url);
			}
			else
			{
				$email = $_POST['email'];
				$first_name = sanitize_text_field( $_POST['first_name'] );
				$last_name = sanitize_text_field( $_POST['last_name'] );

				$result = $this->register_user( $email, $first_name, $last_name );

				if( is_wp_error($result) )
				{
					//Paresd error into a string and append as parameter  to redirect
					$errors = join(',', $result->get_error_codes() );
					$redirect_url = add_query_arg( 'register-errors', $errors, $redirect_url );
				}
				else
				{
					//success, redirect to login page
					$redirect_url = home_url( 'member-login' );
					$redirect_url = add_query_arg( 'registered', $email, $redirect_url );
				}
			}

			wp_redirect($redirect_url);

			exit;
		}
	}

	/**
	 * Register the setting fields needed by the plugin
	 */
	public function register_settings_field() {
		//Create setting fields for the tow keys used by reCAPTCHA
		register_setting('general', 'personalize-login-recaptcha-site-key');
		register_setting('general', 'personalize-login-recaptcha-secret-key');

		add_settings_field(
			'personalize-login-recaptcha-site-key',
			'<label for="personalize-login-recaptcha-site-key">'.__('reCAPTCHA site key', 'storm_login').'</label>',
			array($this, 'render_recaptcha_site_key_field'),
			'general'
		);

		add_settings_field(
			'personalize-login-recaptcha-secret-key',
			'<label for="personalize-login-recaptcha-secret-key">'.__('reCAPTCHA secret key', 'storm_login').'</label>',
			array($this, 'render_recaptcha_secret_key_field'),
			'general'
		);
	}

	public function render_recaptcha_site_key_field() {
		$value = get_option('personalize-login-recaptcha-site-key');
		echo '<input type="text" name="personalize-login-recaptcha-site-key" id="personalize-login-recaptcha-site-key" value="'.esc_attr($value).'" />';
	}

	public function render_recaptcha_secret_key_field() {
		$value = get_option('personalize-login-recaptcha-secret-key');
		echo '<input type="text" name="personalize-login-recaptcha-secret-key" id="personalize-login-recaptcha-secret-key" value="'.esc_attr($value).'" />';
	}

	/**
	 * An action function used to include the reCAPTCHA JavaScript file
	 * at the end of the page.
	 */
	public function add_captcha_js_to_footer() {
	    echo "<script src='https://www.google.com/recaptcha/api.js'></script>";
	}

	/**
	 * Checks that the reCAPTCHA parameter sent with the registration
	 * request is valid.
	 *
	 * @return bool True if the CAPTCHA is OK, otherwise false.
	 */
	private function verify_recaptcha()
	{
		if( isset($_POST['g-recaptcha-response']) )
		{
			 $captcha_response = $_POST['g-recaptcha-response'];
		}
		else
		{
			return false;
		}

		// Verify the captcha response from Google
		    $response = wp_remote_post(
		        'https://www.google.com/recaptcha/api/siteverify',
		        array(
		            'body' => array(
		                'secret' => get_option( 'personalize-login-recaptcha-secret-key' ),
		                'response' => $captcha_response
		            )
		        )
		    );

		    $success = false;
		    if ( $response && is_array( $response ) ) {
		        $decoded_response = json_decode( $response['body'] );
		        $success = $decoded_response->success;
		    }

		    return $success;
	}

	/**
	 * Redirect the user to the custom 'Forgot You Password' page instead of wp-login.php?action=lostpassword
	 * @return [type] [description]
	 */
	public function redirect_to_custom_lostpassword()
	{
		if( $_SERVER['REQUEST_METHOD'] == "GET" )
		{
			if( is_user_logged_in() )
			{
				$this->redirect_logged_in_user();

				exit;
			}
			else
			{
				wp_redirect( home_url( 'member-password-lost' ) );

				exit;
			}
		}
	}

	/**
	 * A Shortcode for rendering form used to initiate the password reset.
	 * @return string  The shortcode output
	 */
	public function render_password_lost_form( $attributes, $content = null )
	{
		//Parse the attributes
		$defualt_attributes = array('show_title' => false);
		$attributes = shortcode_atts($defualt_attributes, $attributes);

		$attributes['errors'] = array();

		if ( isset( $_REQUEST['errors'] ) ) {
		    $error_codes = explode( ',', $_REQUEST['errors'] );

		    foreach ( $error_codes as $error_code ) {
		        $attributes['errors'] []= $this->get_error_message( $error_code );
		    }
		}

		if( is_user_logged_in() )
		{
			return __('You are alreadly signed in', 'storm_login');
		}
		else
	        {
			return $this->get_html_template( 'password_lost_form', $attributes );
		}
	}

	/**
	 * Initiate password reset
	 */
	public function do_password_lost()
	{
		if( $_SERVER['REQUEST_METHOD'] == "POST" )
		{
			$errors = retrieve_password();

			if( is_wp_error($errors) )
			{
				//Error found
				$redirect_url = home_url('member-password-lost');
				$error = join(',', $errors->get_error_codes());
				$redirect_url = add_query_arg('errors', $error, $redirect_url);
			}
			else
			{
				$redirect_url = home_url('member-login');
				$redirect_url = add_query_arg('checkmail', 'confirm', $redirect_url);
			}

			wp_redirect($redirect_url);
			exit;
		}
	}

	/**
	 * Return the message body for the password reset mail
	 * @param  [string] $message    Default mail message
	 * @param  [string] $key        the activation key
	 * @param  [string] $user_login The username for the user
	 * @param  WP_User $user_data  WP_User object
	 * @return [string]            The email message send
	 */
	public function replace_retrieve_password_message( $message, $key, $user_login, $user_data )
	{
		//create new message
		$msg = __('Hello!', 'storm_login') . "\r\n\r\n";
		$msg .= sprintf(__('You asked us to reset your password for your account using the email address %s.', 'storm_login'), $user_login). "\r\n\r\n";
		$msg .= __( "If this was a mistake, or you didn't ask for a password reset, just ignore this email and nothing will happen.", 'storm_login' ) . "\r\n\r\n";
    		$msg .= __( 'To reset your password, visit the following address:', 'storm_login' ) . "\r\n\r\n";
    		$msg .= site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user_login ), 'login' ) . "\r\n\r\n";
    		$msg .= __( 'Thanks!', 'storm_login' ) . "\r\n";

    		return $msg;

	}

	/**
	 * Redirect to the custom password reset page, or the login page if there are error.
	 */
	public function redirect_to_custom_password_reset() {

		if( 'GET' == $_SERVER['REQUEST_METHOD'] )
		{
			list( $rp_path ) = explode( '?', wp_unslash( $_SERVER['REQUEST_URI'] ) );
			$rp_cookie = 'wp-resetpass-cookie';
			if ( isset( $_GET['key'] ) ) {
				$value = sprintf( '%s:%s', wp_unslash( $_GET['login'] ), wp_unslash( $_GET['key'] ) );
				setcookie( $rp_cookie, $value, 0, $rp_path, COOKIE_DOMAIN, is_ssl(), true );

				$redirect_url = home_url('member-password-reset');
				$redirect_url = add_query_arg('key', esc_attr( $_REQUEST['key'] ), $redirect_url);
				$redirect_url = add_query_arg( 'login', esc_attr( $_REQUEST['login'] ), $redirect_url );
				wp_redirect($redirect_url);
				exit;

			}

			if ( isset( $_COOKIE[ $rp_cookie ] ) && 0 < strpos( $_COOKIE[ $rp_cookie ], ':' ) )
			{
				list( $rp_login, $rp_key ) = explode( ':', wp_unslash( $_COOKIE[ $rp_cookie ] ), 2 );
				$user = check_password_reset_key( $rp_key, $rp_login );
				if (  ! hash_equals( $rp_key, $_POST['rp_key'] ) )
				{
					$user = false;
				}
			} else {
				$user = false;
			}

			if ( ! $user || is_wp_error( $user ) )
			{
				setcookie( $rp_cookie, ' ', time() - YEAR_IN_SECONDS, $rp_path, COOKIE_DOMAIN, is_ssl(), true );
				if ( $user && $user->get_error_code() === 'expired_key' )
				{
					wp_safe_redirect( home_url( 'member-login?error=expiredkey' ) );
				}
				else if( $user && $user->get_error_code() === 'invalid_key' )
				{
					wp_safe_redirect( home_url( 'member-login?error=invalidkey' ) );
				}
				exit;
			}

		}
		if( 'POST' == $_SERVER['REQUEST_METHOD'] )
		{
			$rp_key = $_REQUEST['rp_key'];
        		$rp_login = $_REQUEST['rp_login'];
        		$rp_cookie = $_COOKIE['wp-resetpass-cookie'];

        		$user = check_password_reset_key( $rp_key, $rp_login );

        		if ( ! $user || is_wp_error( $user ) ) {
		            if ( $user && $user->get_error_code() === 'expired_key' ) {
		                wp_redirect( home_url( 'member-login?login=expiredkey' ) );
		            } else {
		                wp_redirect( home_url( 'member-login?login=invalidkey' ) );
		            }
		            exit;
		        }

			$errors = new WP_Error();
			if( empty($_POST['pass1']) )
			{
				$errors->add('password_reset_empty', __( "Sorry, we don't accept empty passwords." ) );
			}
			if( $_POST['pass1'] !== $_POST['pass2'] )
			{
				$errors->add('password_reset_mismatch', __("The two passwords you entered don't match.") );
			}
			if ( ( ! $errors->get_error_code() ) && isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) )
			{
				reset_password($user, $_POST['pass1']);
				setcookie( $rp_cookie, ' ', time() - YEAR_IN_SECONDS, $rp_path, COOKIE_DOMAIN, is_ssl(), true );
				wp_redirect( home_url( 'member-login?password=changed' ) );
				exit;
			}
		}
	}

	/**
	 * A shortcode for rendering the form used to reset a user's password
	 * @return [type] [description]
	 */
	public function render_password_reset_form( $attributes, $content = null )
	{
		//Prase the shortcode
		$defualt_attributes = array('show_title' => false);
		$attributes = shortcode_atts($defualt_attributes, $attributes);

		if(is_user_logged_in())
		{
			return __('You are alreadly signed in!', 'storm_login');
		}
		else
		{

			if( isset( $_REQUEST['key'] ) && isset( $_REQUEST['login'] ) )
			{
				$attributes['rp_key'] =$_REQUEST['key'];
				$attributes['rp_login'] = $_REQUEST['login'];

				//Error message
				$attributes['errors'] = array();

				if ( isset( $_REQUEST['error'] ) ) {
				    $error_codes = explode( ',', $_REQUEST['error'] );

				    foreach ( $error_codes as $error_code ) {
				        $attributes['errors'] []= $this->get_error_message( $error_code );
				    }
				}

				return $this->get_html_template('password_reset_form', $attributes);
			}
			else
			{
				return __('Invalid password reset link.', 'storm_login');
			}
		}
	}

	/**
	 * Reset the user's password if the password reset form was submitted.
	 * @return [type] [description]
	 */
	public function do_password_reset() {

	    if ( 'POST' == $_SERVER['REQUEST_METHOD'] ) {
	        $rp_key = $_REQUEST['rp_key'];
	        $rp_login = $_REQUEST['rp_login'];

	        // $user = check_password_reset_key( $rp_key, $rp_login );

	        // if ( ! $user || is_wp_error( $user ) ) {
	        //     if ( $user && $user->get_error_code() === 'expired_key' ) {
	        //         wp_redirect( home_url( 'member-login?login=expiredkey' ) );
	        //     } else {
	        //         wp_redirect( home_url( 'member-login?login=invalidkey' ) );
	        //     }
	        //     exit;
	        // }

	        if ( isset( $_POST['pass1'] ) ) {
	             if ( empty( $_POST['pass1'] ) ) {
	                // Password is empty
	                $redirect_url = home_url( 'member-password-reset' );

	                $redirect_url = add_query_arg( 'key', $rp_key, $redirect_url );
	                $redirect_url = add_query_arg( 'login', $rp_login, $redirect_url );
	                $redirect_url = add_query_arg( 'error', 'password_reset_empty', $redirect_url );

	                wp_redirect( $redirect_url );
	                exit;
	            }

	            if ( $_POST['pass1'] != $_POST['pass2'] ) {
	                // Passwords don't match
	                $redirect_url = home_url( 'member-password-reset' );

	                $redirect_url = add_query_arg( 'key', $rp_key, $redirect_url );
	                $redirect_url = add_query_arg( 'login', $rp_login, $redirect_url );
	                $redirect_url = add_query_arg( 'error', 'password_reset_mismatch', $redirect_url );

	                wp_redirect( $redirect_url );
	                exit;
	            }

	            // Parameter checks OK, reset password
	            reset_password( $user, $_POST['pass1'] );
	            wp_redirect( home_url( 'member-login?password=changed' ) );
	        } else {
	            echo "Invalid request.";
	        }

	        exit;
	    }
	}
}

//initializes the plugin
$personalize_login_pages_plugin = new Personalize_Login_Plugin();

//Create the custom page at  plugin is activation
register_activation_hook( __FILE__, array( 'Personalize_Login_Plugin', 'plugin_activeted') );
register_deactivation_hook( __FILE__, array( 'Personalize_Login_Plugin', 'plugin_deactiveted' ) );

