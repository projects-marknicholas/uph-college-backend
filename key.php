<?php
class SecurityKey {
  private $conn;

  public function __construct($dbConnection) {
    $this->conn = $dbConnection;
  }

  public function validateBearerToken() {
    // Access Authorization header directly from getallheaders()
    $headers = getallheaders();
    $bearerToken = isset($headers['Authorization']) ? trim(str_replace('Bearer ', '', $headers['Authorization'])) : '';

    // Validate the Bearer token against the users table
    if (empty($bearerToken)) {
      return ['status' => 'error', 'message' => 'Authorization token is required'];
    }

    $stmt = $this->conn->prepare("SELECT user_id, security_key, role FROM users WHERE security_key = ?");
    $stmt->bind_param("s", $bearerToken);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
      $stmt->close();
      return ['status' => 'error', 'message' => 'Invalid authorization token'];
    }

    // Fetch the user's id and role
    $row = $result->fetch_assoc();
    $user_id = $row['user_id'];
    $user_role = $row['role'];
    $stmt->close();

    // Return success along with the user's id and role
    return ['status' => 'success', 'user_id' => $user_id, 'role' => $user_role];
  }
}
?>
