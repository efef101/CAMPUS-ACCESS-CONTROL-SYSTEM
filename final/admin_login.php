<?php
// The admin signs in on login.php now (one login page for every role).
// This file only forwards there, so old links keep working.
header("Location: login.php");
exit;