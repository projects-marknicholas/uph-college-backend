<?php
class ActivityLogger {
  private $conn;

  public function __construct($dbConnection) {
    $this->conn = $dbConnection;
  }

  public function logActivity($userId, $action, $title, $description) {
    // Set the time zone
    date_default_timezone_set('Asia/Manila');
    
    // Get the current timestamp
    $created_at = date('Y-m-d H:i:s');
    
    // Prepare the SQL query to insert the activity
    $stmt = $this->conn->prepare("INSERT INTO activities (user_id, action, title, description, created_at) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("sssss", $userId, $action, $title, $description, $created_at);
    
    // Execute the query and handle any errors
    if ($stmt->execute()) {
      return ['status' => 'success', 'message' => 'Activity logged successfully'];
    } else {
      return ['status' => 'error', 'message' => 'Error logging activity: ' . $this->conn->error];
    }
  }
}
?>
