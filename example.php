<pre>
<?php	
	include "class.emailverify.php";
	
	$verify = new EmailVerify();

	if($verify->verify('musa@bglobalsourcing.com')){
		echo 'Email address exists';
	}else{
		echo 'Invalid Email Address';
	}
	
?>
</pre>