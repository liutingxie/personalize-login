<?php if($attributes['show_title']) : ?>
	<h3><?php _e('Register', 'storm_login'); ?></h3>
<?php endif; ?>

<?php if( count($attributes['errors']) > 0 ) : ?>
	<?php foreach ($attributes['errors'] as $error) : ?>
		<p><?php echo $error; ?></p>
	<?php endforeach; ?>
<?php endif; ?>
<div id="register-form" class="widecolumn">
	<form action="<?php echo wp_registration_url(); ?>" method="post">
		<p class="form-now">
			<lable for="email"><?php _e('Email', 'storm_login'); ?> <strong>*</strong></lable>
			<input type="text" name="email" id="email">
		</p>
		<p class="form-now">
			<lable for="first_name"><?php _e('First Name', 'storm_login'); ?></lable>
			<input type="text" name="first_name" id="first_name">
		</p>
		<p class="form-now">
			<lable for="last_name"><?php _e('Last Name', 'storm_login'); ?></lable>
			<input type="text" name="last_name" id="last_name">
		</p>
		<p class="form-now">
			<?php _e('Note: Your password will be generated automatically and sent to your email address.', 'storm_login'); ?>
		</p>
		<?php if( $attributes['recaptcha_site_key']) : ?>
			<div class="recaptcha-container">

				<div class="g-recaptcha" data-sitekey="6LcmsRITAAAAAI48Oo2Ow1I-aiHEwauCjXUaeymX"></div>

			</div>

		<?php endif; ?>
		<p class="signup-submit">
			<input type="submit" name="submit" class="register-button" value="<?php _e('Register','storm_login'); ?>"
			>
		</p>
	</form>
</div>