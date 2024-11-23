<?php
use myPHPnotes\Microsoft\Auth;
use myPHPnotes\Microsoft\Handlers\Session;
use myPHPnotes\Microsoft\Models\User;
session_start();

class AuthController {
  public function register() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = bin2hex(random_bytes(16));
    $profile = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png';
    $last_name = htmlspecialchars($data['last_name'] ?? '');
    $first_name = htmlspecialchars($data['first_name'] ?? '');
    $email = htmlspecialchars($data['email'] ?? '');
    $password = htmlspecialchars($data['password'] ?? '');
    $confirm_password = htmlspecialchars($data['confirm_password'] ?? '');
    $role = 'pending';
    $joined_at = date('Y-m-d H:i:s');
    $security_key = bin2hex(random_bytes(16));

    if(empty($last_name)){
      $response['status'] = 'error';
      $response['message'] = 'Last name cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($first_name)){
      $response['status'] = 'error';
      $response['message'] = 'First name cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($email)){
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if(empty($password)){
      $response['status'] = 'error';
      $response['message'] = 'Password cannot be empty';
      echo json_encode($response);
      return;
    } else if(strlen($password) < 6){
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long';
      echo json_encode($response);
      return;
    } else if(!preg_match('/[A-Z]/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one uppercase letter';
      echo json_encode($response);
      return;
    } else if(!preg_match('/[a-z]/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one lowercase letter';
      echo json_encode($response);
      return;
    } else if(!preg_match('/\d/', $password)){
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one number';
      echo json_encode($response);
      return;
    }
    
    if(empty($confirm_password)){
      $response['status'] = 'error';
      $response['message'] = 'Confirm Password cannot be empty';
      echo json_encode($response);
      return;
    } else if($password != $confirm_password){
      $response['status'] = 'error';
      $response['message'] = 'Password do not match';
      echo json_encode($response);
      return;
    }

    // Check if the user already exists
    $stmt = $conn->prepare("SELECT email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user already exists';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Insert data
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare('INSERT INTO users (user_id, profile, last_name, first_name, email, password, role, security_key, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('sssssssss', $user_id, $profile, $last_name, $first_name, $email, $hashed_password, $role, $security_key, $joined_at);
    
    if ($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'User created successfully';
      echo json_encode($response);
      return;
    } else{
      $response['status'] = 'error';
      $response['message'] = 'Error creating user: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }
  
  public function login() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars($data['email'] ?? '');
    $password = htmlspecialchars($data['password'] ?? '');
    $joined_at = date('Y-m-d H:i:s');
    
    if(empty($email)){
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if(empty($password)){
      $response['status'] = 'error';
      $response['message'] = 'Password cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if user exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Email or password is incorrect';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();

    if (!password_verify($password, $user['password'])) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email or password.';
      echo json_encode($response);
      return;
    } else {
      // Check if the user is deactivated
      if ($user['status'] === 'deactivated') {
        $response['status'] = 'error';
        $response['message'] = 'Your account has been deactivated.';
        echo json_encode($response);
        return;
      }

      // Check if the role is pending
      if ($user['role'] === 'pending') {
        $response['status'] = 'error';
        $response['message'] = 'Your account is not yet approved.';
        echo json_encode($response);
        return;
      }

      // Update the last_login field upon successful login
      $update_stmt = $conn->prepare("UPDATE users SET last_login = ? WHERE email = ?");
      $update_stmt->bind_param("ss", $joined_at, $email);
      $update_stmt->execute();
      $update_stmt->close();

      $response['status'] = 'success';
      $response['message'] = 'Login successful.';
      $response['user'] = [
        'profile' => $user['profile'],
        'user_id' => $user['user_id'],
        'email' => $user['email'],
        'first_name' => ucwords(strtolower($user['first_name'])),
        'last_name' => ucwords(strtolower($user['last_name'])),
        'role' => $user['role'],
        'status' => $user['status']
      ];
      echo json_encode($response);
      return;
    }
  }
  
  public function forgot_password() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars($data['email'] ?? '');

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    // Check if the email exists in the database
    $stmt = $conn->prepare("SELECT id, first_name FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'No user found with this email address';
      echo json_encode($response);
      return;
    }

    $user = $result->fetch_assoc();
    $token = bin2hex(random_bytes(16));

    // Update the token in the database
    $stmt = $conn->prepare("UPDATE users SET token = ? WHERE email = ?");
    $stmt->bind_param("ss", $token, $email);

    if($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'Token generated successfully';
      $response['data'] = array(
        'first_name' => ucwords(strtolower($user['first_name'])),
        'email' => $email,
        'token' => $token
      );

      echo json_encode($response);
      return;
    } else{
      $response['status'] = 'error';
      $response['message'] = 'Failed to update token';
      echo json_encode($response);
      return;
    }

    $stmt->close();
  }
  
  public function reset_password() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $email = htmlspecialchars($_GET['email'] ?? '');
    $token = htmlspecialchars($_GET['token'] ?? '');
    $new_password = htmlspecialchars($data['new_password'] ?? '');
    $confirm_password = htmlspecialchars($data['confirm_password'] ?? '');

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email cannot be empty';
      echo json_encode($response);
      return;
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format';
      echo json_encode($response);
      return;
    }

    if (empty($token)) {
      $response['status'] = 'error';
      $response['message'] = 'Token cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'New password cannot be empty';
      echo json_encode($response);
      return;
    } else if (strlen($new_password) < 6) {
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long';
      echo json_encode($response);
      return;
    } else if (!preg_match('/[A-Z]/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one uppercase letter';
      echo json_encode($response);
      return;
    } else if (!preg_match('/[a-z]/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one lowercase letter';
      echo json_encode($response);
      return;
    } else if (!preg_match('/\d/', $new_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password must contain at least one number';
      echo json_encode($response);
      return;
    }

    if (empty($confirm_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Confirm Password cannot be empty';
      echo json_encode($response);
      return;
    } else if ($new_password != $confirm_password) {
      $response['status'] = 'error';
      $response['message'] = 'Passwords do not match';
      echo json_encode($response);
      return;
    }

    // Check if the token is valid
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND token = ?");
    $stmt->bind_param("ss", $email, $token);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'Invalid token or email';
      echo json_encode($response);
      return;
    }

    // Token is valid, update the password
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password = ?, token = NULL WHERE email = ?");
    $stmt->bind_param("ss", $hashed_password, $email);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Password reset successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error resetting password: ' . $conn->error;
      echo json_encode($response);
      return;
    }
    
    $stmt->close();
  }

  // public function google_auth() {
  //   global $conn;
  //   date_default_timezone_set('Asia/Manila');
  //   $response = array();
  
  //   // Allow cross-origin requests
  //   header('Access-Control-Allow-Origin: *');
  //   header('Content-Type: application/json');
  
  //   // Config
  //   $clientID = '65097369228-9skupna3f149vi07aof4ugmtadao5und.apps.googleusercontent.com';
  //   $clientSecret = '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';
  //   $redirectUri = 'http://localhost:3000/';
  
  //   // Create Client Request to access Google API
  //   $client = new Google_Client();
  //   $client->setClientId($clientID);
  //   $client->setClientSecret($clientSecret);
  //   $client->setRedirectUri($redirectUri);
  //   $client->addScope("email");
  //   $client->addScope("profile");
  
  //   // Authenticate code from Google OAuth Flow
  //   if (isset($_GET['code'])) {
  //     $token = $client->fetchAccessTokenWithAuthCode($_GET['code']);
  
  //     if (isset($token['error'])) {
  //       $response['status'] = 'error';
  //       $response['message'] = htmlspecialchars($token['error']);
  //       echo json_encode($response);
  //       exit;
  //     }
  
  //     $client->setAccessToken($token['access_token']);
  //     $google_oauth = new Google_Service_Oauth2($client);
  
  //     try {
  //       $google_account_info = $google_oauth->userinfo->get();
  //       $email = $google_account_info->email;
  //       $name = $google_account_info->name;
  //       $givenName = $google_account_info->givenName;
  //       $familyName = $google_account_info->familyName;
  //       $picture = $google_account_info->picture;
  //       $login_at = date('Y-m-d H:i:s');
  
  //       // Check if the user exists in the database
  //       $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
  //       $stmt->bind_param("s", $email);
  //       $stmt->execute();
  //       $result = $stmt->get_result();
  
  //       if ($result->num_rows > 0) {
  //         // User exists
  //         $user = $result->fetch_assoc();
  //         $response['status'] = 'success';
  //         $response['message'] = 'Login successful.';
  //         $response['user'] = [
  //           'profile' => $user['profile'] ?? '',
  //           'user_id' => $user['user_id'],
  //           'email' => $user['email'],
  //           'last_name' => $user['last_name'],
  //           'first_name' => $user['first_name'],
  //           'role' => $user['role']
  //         ];
  //         // Update the last_login field upon successful login
  //         $update_stmt = $conn->prepare("UPDATE users SET last_login = ? WHERE email = ?");
  //         $update_stmt->bind_param("ss", $login_at, $email);
  //         $update_stmt->execute();
  //         $update_stmt->close();
  //       } else {
  //         $user_id = bin2hex(random_bytes(16));
  //         $defaultPassword = password_hash('defaultpassword', PASSWORD_BCRYPT);
  //         $role = 'pending';
  //         $security_key = bin2hex(random_bytes(16));
  //         $createdAt = date('Y-m-d H:i:s');
  
  //         $stmt = $conn->prepare("INSERT INTO users (profile, user_id, last_name, first_name, email, password, role, security_key, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
  //         $stmt->bind_param("sssssssss", $picture, $user_id, $familyName, $givenName, $email, $defaultPassword, $role, $security_key, $createdAt);
  //         $stmt->execute();
  
  //         // Retrieve the newly inserted user
  //         $user_id = $stmt->insert_id;
  //         $response['status'] = 'success';
  //         $response['user'] = [
  //           'profile' => $picture ?? '',
  //           'user_id' => $user_id,
  //           'email' => $email,
  //           'last_name' => $familyName,
  //           'first_name' => $givenName,
  //           'role' => 'pending'
  //         ];
  //       }
  
  //       $stmt->close();
  //       echo json_encode($response);
  //       exit;
  //     } catch (Exception $e) {
  //       $response['status'] = 'error';
  //       $response['message'] = htmlspecialchars($e->getMessage());
  //       echo json_encode($response);
  //       return;
  //     }
  //   } else {
  //     header('Location: ' . $client->createAuthUrl());
  //     exit;
  //   }
  // }

  public function google_auth() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Allow cross-origin requests
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json');
  
    // Config
    $clientID = '65097369228-9skupna3f149vi07aof4ugmtadao5und.apps.googleusercontent.com';
    $clientSecret = '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';
    $redirectUri = 'http://localhost:3000/';
  
    // Create Client Request to access Google API
    $client = new Google_Client();
    $client->setClientId($clientID);
    $client->setClientSecret($clientSecret);
    $client->setRedirectUri($redirectUri);
    $client->addScope("email");
    $client->addScope("profile");
  
    // Authenticate code from Google OAuth Flow
    if (isset($_GET['code'])) {
      $token = $client->fetchAccessTokenWithAuthCode($_GET['code']);
  
      if (isset($token['error'])) {
        $response['status'] = 'error';
        $response['message'] = htmlspecialchars($token['error']);
        echo json_encode($response);
        exit;
      }
  
      $client->setAccessToken($token['access_token']);
      $google_oauth = new Google_Service_Oauth2($client);
  
      try {
        $google_account_info = $google_oauth->userinfo->get();
        $email = $google_account_info->email;
        $name = $google_account_info->name;
        $givenName = $google_account_info->givenName;
        $familyName = $google_account_info->familyName;
        $picture = $google_account_info->picture;
        $login_at = date('Y-m-d H:i:s');
  
        // Check if the user exists in the database
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
  
        if ($result->num_rows > 0) {
          // User exists
          $user = $result->fetch_assoc();

          $response['status'] = 'success';
          $response['message'] = 'Login successful.';
          $response['user'] = [
            'profile' => $user['profile'] ?? '',
            'user_id' => $user['user_id'],
            'email' => $user['email'],
            'last_name' => $user['last_name'],
            'first_name' => $user['first_name'],
            'role' => $user['role'],
            'status' => $user['status']
          ];

          // Update the last_login field upon successful login
          $update_stmt = $conn->prepare("UPDATE users SET last_login = ? WHERE email = ?");
          $update_stmt->bind_param("ss", $login_at, $email);
          $update_stmt->execute();
          $update_stmt->close();
        } else {
          $user_id = bin2hex(random_bytes(16));
          $defaultPassword = password_hash('defaultpassword', PASSWORD_BCRYPT);
          $role = 'pending';
          $security_key = bin2hex(random_bytes(16));
          $createdAt = date('Y-m-d H:i:s');
  
          $stmt = $conn->prepare("INSERT INTO users (profile, user_id, last_name, first_name, email, password, role, security_key, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
          $stmt->bind_param("sssssssss", $picture, $user_id, $familyName, $givenName, $email, $defaultPassword, $role, $security_key, $createdAt);
          $stmt->execute();
  
          // Retrieve the newly inserted user
          $user_id = $stmt->insert_id;
          $response['status'] = 'success';
          $response['user'] = [
            'profile' => $picture ?? '',
            'user_id' => $user_id,
            'email' => $email,
            'last_name' => $familyName,
            'first_name' => $givenName,
            'role' => 'pending'
          ];
        }
  
        $stmt->close();
        echo json_encode($response);
        exit;
      } catch (Exception $e) {
        $response['status'] = 'error';
        $response['message'] = htmlspecialchars($e->getMessage());
        echo json_encode($response);
        return;
      }
    } else {
      header('Location: ' . $client->createAuthUrl());
      exit;
    }
  } 

  public function microsoft_signin(){
    $tenant = "common";
    $client_id = "3e3ec2ce-f7af-4f40-91c4-cd537e80203e";
    $client_secret = "cf.8Q~bOMXNq17Mu3gGiUTlhnUQWMAA2sewMha.Q";
    $callback = "http://localhost/uph-college/api/auth/microsoft";
    $scopes = ["User.Read"];

    $microsoft = new Auth($tenant, $client_id, $client_secret, $callback, $scopes);
    $authUrl = $microsoft->getAuthUrl();
    echo $authUrl;
    $parsedUrl = parse_url($authUrl);
    parse_str($parsedUrl['query'], $queryParams);
    $stateFromUrl = isset($queryParams['state']) ? $queryParams['state'] : 'State not found';
    Session::set('oauth_state', $stateFromUrl);
    header("location: " . $microsoft->getAuthUrl());
  }

  public function microsoft_auth() {
    // Check if state matches
    if (!isset($_REQUEST['state']) || $_REQUEST['state'] !== Session::get('oauth_state')) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid state parameter.']);
      return;
    }

    // Initialize the Auth object with session credentials
    $auth = new Auth(
      Session::get("tenant_id"),
      Session::get("client_id"),
      Session::get("client_secret"),
      Session::get("redirect_uri"),
      Session::get("scopes")
    );
  
    // Retrieve tokens
    $tokens = $auth->getToken($_REQUEST['code'], $_REQUEST['state']);
    $accessToken = $tokens->access_token;
  
    // Set the access token to the Auth object
    $auth->setAccessToken($accessToken);
  
    // Fetch user data
    $user = new User();
    $surname = $user->data->getSurname();
    $givenName = $user->data->getGivenName();
    $email = $user->data->getUserPrincipalName();
  
    // Check if the user already exists
    global $conn; // Ensure you have access to the database connection
    $stmt = $conn->prepare("SELECT profile, user_id, first_name, last_name, role, status, email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows > 0) {
      // User exists, fetch user details
      $userData = $result->fetch_assoc();
      $stmt->close();
  
      // Return user credentials
      $response = [
        'status' => 'success',
        'message' => 'Login successful.',
        'user' => [
          'profile' => $userData['profile'] ?? null,
          'user_id' => $userData['user_id'] ?? null,
          'email' => $userData['email'],
          'first_name' => ucwords(strtolower($userData['first_name'] ?? '')),
          'last_name' => ucwords(strtolower($userData['last_name'] ?? '')),
          'role' => $userData['role'] ?? null,
          'status' => $userData['status'] ?? null
        ]
      ];
      echo json_encode($response);
      return;
    }
  
    // If the user does not exist, register the user
    $user_id = bin2hex(random_bytes(16));
    $profile = 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png';
    $role = 'pending';
    $joined_at = date('Y-m-d H:i:s');
    $security_key = bin2hex(random_bytes(16));
  
    // Insert new user into the database
    $stmt = $conn->prepare('INSERT INTO users (user_id, profile, last_name, first_name, email, password, role, security_key, joined_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    // Set the password to a random string or any default password since it's a social login
    $defaultPassword = password_hash($user_id, PASSWORD_DEFAULT);
    $stmt->bind_param('sssssssss', $user_id, $profile, $surname, $givenName, $email, $defaultPassword, $role, $security_key, $joined_at);
  
    if ($stmt->execute()) {
      $stmt->close();
  
      $response = [
        'status' => 'success',
        'message' => 'User registered successfully.',
        'user' => [
          'profile' => $profile,
          'user_id' => $user_id,
          'email' => $email,
          'first_name' => ucwords(strtolower($givenName)),
          'last_name' => ucwords(strtolower($surname)),
          'role' => $role,
          'status' => 'pending'
        ]
      ];
      echo json_encode($response);
    } else {
      $stmt->close();
      $response = [
        'status' => 'error',
        'message' => 'Error creating user: ' . $conn->error
      ];
      echo json_encode($response);
    }
  }  

  public function security_key() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Get the API key from the Authorization header
    $headers = apache_request_headers();
    $api_key = isset($headers['Authorization']) ? trim(str_replace('Bearer ', '', $headers['Authorization'])) : '';
  
    // Validate the API key
    if ($api_key !== 'ZgnJxCp7R2i95Y3Y7wMN6VTryZ0Ro3a1letBoUyYi5MyKIyW5EQTTvwDqsJU5xVG') {
      $response['status'] = 'error';
      $response['message'] = 'Invalid API key.';
      echo json_encode($response);
      return;
    }
  
    // Get the user ID from the query parameter
    $user_id = htmlspecialchars($_GET['user_id'] ?? '');
  
    // Check if the user ID is empty
    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID is required.';
      echo json_encode($response);
      return;
    }
  
    // Query to check if user exists and retrieve the security key
    $stmt = $conn->prepare("SELECT security_key FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'User not found.';
      echo json_encode($response);
      return;
    }
  
    $user = $result->fetch_assoc();
    $stored_security_key = $user['security_key'];
  
    $response['status'] = 'success';
    $response['message'] = 'User found.';
    $response['security_key'] = $stored_security_key;
    echo json_encode($response);
    return;
  }        
}

?>