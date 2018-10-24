<div class="login-form-container">
	<!-- Show errors if there are any -->
<?php if ( count( $attributes['errors'] ) > 0 ) : ?>
    <?php foreach ( $attributes['errors'] as $error ) : ?>
        <p class="login-error">
            <?php echo $error; ?>
        </p>
    <?php endforeach; ?>
<?php endif; ?>

	<!-- Show logged out message if user just logged out -->
	<?php if ( $attributes['logged_out'] ) : ?>
    <p class="login-info">
        <?php _e( 'You have signed out. Would you like to sign in again?', 'personalize-login' ); ?>
    </p>
<?php endif; ?>

<!-- Show successful if user just registered -->
<?php if( $attributes['registered'] ) :?>
	<p class="login-info">
		<?php printf( __('You have successful registered to <strong> %s </strong>. we have emailed your password to the emaill address you entered ', 'storm_login'), bloginfo('name') ); ?>
	</p>
<?php endif; ?>

<?php if( $attributes['lost_password_sent'] ) : ?>
	<p class="login-info">
		<?php _e('Check your email for a link to reset your password.', 'storm_login'); ?>
	</p>
<?php endif; ?>

<?php if ( $attributes['password_updated'] ) : ?>
    <p class="login-info">
        <?php _e( 'Your password has been changed. You can sign in now.', 'personalize-login' ); ?>
    </p>
<?php endif; ?>
	

	<form action="<?php echo wp_login_url(); ?>" method="post">
		<p class="login-username">
			<lable for="user_login"><?php _e('Email', 'storm_login'); ?></lable>
			<input type="text" name="log" id="user_login">
		</p>
		<p class="login-password">
			<lable for="user_pwd"><?php _e('Password', 'storm_login'); ?></lable>
			<input type="password" name="pwd" id="user_pwd">
		</p>
		<p class="forgetmenot">
			<label for="rememberme">
				<input type="checkbox" name="rememberme" id="rememberme">
				<?php _e('Remember Me', 'storm_login'); ?>
			</label>
		</p>
		<p class="login-submit">
			<input type="submit" value="<?php _e('Sign in', 'storm_login'); ?>">
		</p>
		<p id="nav">
			<a href="<?php echo wp_lostpassword_url(); ?>">
				<?php _e('Forgot you password'); ?>
			</a>
		</p>
	</form>
</div>