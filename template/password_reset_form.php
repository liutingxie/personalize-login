<diiv id="password-reset-form">
	<?php if($attributes['show_title']) : ?>
		<p>
			<?php _e('Pick a New Password', 'storm_login'); ?>
		</p>
	<?php endif; ?>

	<form name="resetpassoform" id="resetpassoform" action="<?php  echo site_url('wp-login.php?action=resetpass');?>" method="post" autocomplete="off">
		<input type="hidden"  id="user_login" name="rp_login" value="<?php echo esc_attr($attributes['rp_login']); ?>">
		<input type="hidden" name="rp_key" value="<?php echo esc_attr($attributes['rp_key']) ?>">

        	<?php if ( count( $attributes['errors'] ) > 0 ) : ?>
	            <?php foreach ( $attributes['errors'] as $error ) : ?>
	                <p>
	                    <?php echo $error; ?>
	                </p>
	            <?php endforeach; ?>
		<?php endif; ?>
		<p>
			<label for="pass1"><?php _e('New assword', 'storm_login');  ?></label>
			<input type="password" name="pass1" id="pass1" class="input" value="" autocomplete="off">
		</p>
		<p>
			<label for="pass2"><?php _e('Repeat new password');?></label>
			<input type="password" name="pass2" id="pass2" class="input" value="" autocomplete="off">
		</p>
		<p class="description"><?php echo wp_get_password_hint();  ?></p>
		<p class="resetpass-submit">
			<input type="submit" class="button" id="resetpass-button" name="submit" value="<?php _e('Reset Password', 'storm_login'); ?>">
		</p>
	</form>
</diiv>