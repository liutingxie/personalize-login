 <?php if( $attributes['show_title'] ) : ?>
 	<h3><?php _e('Forgot You Password?', 'storm_login'); ?></h3>
 <?php endif; ?>
 <?php if(count($attributes['errors']) > 0) : ?>
 		<?php foreach ($attributes['errors'] as $error) : ?>
 			<p><?php echo $error; ?></p>
		<?php endforeach; ?>
<?php endif; ?>

 	<p>
 		<?php _e("Enter your email address and we'll send you a link you can use to pick a new password.",
                'storm_login'); ?>
 	</p>
<form action="<?php echo wp_lostpassword_url(); ?>" method="post" class="lostpasswordform">
	<p class="form-row">
		<label for="user_login"><?php _e('Email', 'storm_login'); ?></label>
		<input type="text" name="user_login" id="user_login">
	</p>
	<p class="lostpassword-submit">
		<input type="submit" name="submit" id="ostpassword-button" value="<?php _e('Reset Password', 'storm_login'); ?> ">
	</p>
</form>