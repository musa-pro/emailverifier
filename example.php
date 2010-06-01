<pre>
<?php	
	include "class.emailverify.php";
	
	$verify = new EmailVerify();
	$verify->debug_on = true;

	$verify->local_user = 'info';	//username of your address from which you are sending message to verify
	$verify->local_host = 'mydomain.com';	//domain name of your address

	if($verify->verify('example@example.com')){
		echo 'Valid email address';
	}else{
		echo 'Invalid Email Address';
	}
	
?>
</pre>