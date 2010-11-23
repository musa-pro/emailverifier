<pre>
<?php	
	include "class.emailverify.php";
	
	$verify = new EmailVerify();
	$verify->debug_on = true;

	$verify->local_user = 'localuser';	//username of your address from which you are sending message to verify
	$verify->local_host = 'localhost';	//domain name of your address

	if($verify->verify('yourname@yourdomain.com')){
		echo 'Valid email address';
	}else{
		echo 'Invalid Email Address';
	}
	
?>
</pre>