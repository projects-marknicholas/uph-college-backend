<?php
class AdminController{
  // Scholarship Type
  public function add_scholarship_type(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $scholarship_type_id = bin2hex(random_bytes(16));
    $scholarship_type = htmlspecialchars($data['scholarship_type'] ?? '');
    $category = htmlspecialchars($data['category'] ?? '');
    $description = htmlspecialchars($data['description'] ?? '');
    $eligibility = htmlspecialchars($data['eligibility'] ?? '');
    $created_at = date('Y-m-d H:i:s');

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    if(empty($scholarship_type)){
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($category)){
      $response['status'] = 'error';
      $response['message'] = 'Category cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($description)){
      $response['status'] = 'error';
      $response['message'] = 'Description cannot be empty';
      echo json_encode($response);
      return;
    }

    if(empty($eligibility)){
      $response['status'] = 'error';
      $response['message'] = 'Eligibility cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if the scholarship type already exists
    $lowered_st = strtolower($scholarship_type);
    $stmt = $conn->prepare("SELECT scholarship_type FROM scholarship_types WHERE scholarship_type = ?");
    $stmt->bind_param("s", $lowered_st);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This scholarship type already exists';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Insert data
    $stmt = $conn->prepare('INSERT INTO scholarship_types (scholarship_type_id, scholarship_type, category, description, eligibility, created_at) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('ssssss', $scholarship_type_id, $scholarship_type, $category, $description, $eligibility, $created_at);
    
    if ($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'Scholarship type created successfully';

      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'scholarship type',          
        'added a scholarship type',      
        'Added new scholarship type: ' . $scholarship_type 
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }

      echo json_encode($response);
      return;
    } else{
      $response['status'] = 'error';
      $response['message'] = 'Error creating scholarship type: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }
  
  public function get_scholarship_type() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
    
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
    
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
    
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
    
    // Get the current page and the number of records per page from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
    
    // Fetch scholarship types with pagination
    $stmt = $conn->prepare("
      SELECT scholarship_type_id, scholarship_type, category, 
           description, eligibility, archive, created_at
      FROM scholarship_types 
      ORDER BY created_at DESC
      LIMIT ?, ?
    ");
    
    if (!$stmt) {
      echo json_encode(['status' => 'error', 'message' => 'SQL error: ' . $conn->error]);
      return;
    }
  
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
    
    // Get total number of records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM scholarship_types");
    
    if (!$total_stmt) {
      echo json_encode(['status' => 'error', 'message' => 'SQL error: ' . $conn->error]);
      return;
    }
    
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
    
    if ($result->num_rows > 0) {
      $scholarship_types = array();
    
      while ($row = $result->fetch_assoc()) {
        // Fetch associated types for each scholarship type
        $type_id = $row['scholarship_type_id'];
        $type_stmt = $conn->prepare("SELECT type_id, type, description, eligibility, archive, created_at 
                        FROM types 
                        WHERE scholarship_type_id = ?");
        if ($type_stmt) {
          $type_stmt->bind_param("s", $type_id);
          $type_stmt->execute();
          $type_result = $type_stmt->get_result();
  
          // Construct type_list
          $type_list = array();
          while ($type_row = $type_result->fetch_assoc()) {
            $type_list[] = $type_row;
          }
  
          // Add type_list and count to the current scholarship type
          $row['type_list'] = $type_list;
          $row['type'] = count($type_list); // Count of associated types
          $type_stmt->close();
        } else {
          // Handle error in fetching types
          $row['type_list'] = [];
          $row['type'] = 0; // No types found
        }
  
        $scholarship_types[] = $row;
      }
    
      $response['status'] = 'success';
      $response['data'] = $scholarship_types;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No scholarship types found';
    }
    
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }  

  public function update_scholarship_type() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $data = json_decode(file_get_contents("php://input"), true);
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');
    $scholarship_type = htmlspecialchars($data['scholarship_type'] ?? '');
    $category = htmlspecialchars($data['category'] ?? '');
    $description = htmlspecialchars($data['description'] ?? '');
    $eligibility = htmlspecialchars($data['eligibility'] ?? '');
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    if (empty($scholarship_type_id)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type ID cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Check if the scholarship type does not exist
    $lowered_st = strtolower($scholarship_type);
    $stmt = $conn->prepare("SELECT scholarship_type FROM scholarship_types WHERE scholarship_type = ? AND scholarship_type_id != ?");
    $stmt->bind_param("ss", $lowered_st, $scholarship_type_id);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Check if no records were found
    if ($result->num_rows > 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This scholarship type already exists';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  
    if (empty($scholarship_type)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($category)) {
      $response['status'] = 'error';
      $response['message'] = 'Category cannot be empty';
      echo json_encode($response);
      return;
    }
  
    if (empty($description)) {
      $response['status'] = 'error';
      $response['message'] = 'Description cannot be empty';
      echo json_encode($response);
      return;
    }
  
    if (empty($eligibility)) {
      $response['status'] = 'error';
      $response['message'] = 'Eligibility cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Update the scholarship type
    $stmt = $conn->prepare('UPDATE scholarship_types SET scholarship_type = ?, category = ?, description = ?, eligibility = ? WHERE scholarship_type_id = ?');
    $stmt->bind_param('sssss', $scholarship_type, $category, $description, $eligibility, $scholarship_type_id);
  
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Scholarship type updated successfully';

      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'scholarship type',          
        'updated a scholarship type',      
        'Updated the scholarship type: ' . $scholarship_type 
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }

      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating scholarship type: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }  

  public function delete_scholarship_type() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Extract scholarship type ID
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    if (empty($scholarship_type_id)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type ID cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Check if the scholarship type exists
    $stmt = $conn->prepare("SELECT scholarship_type_id FROM scholarship_types WHERE scholarship_type_id = ?");
    $stmt->bind_param("s", $scholarship_type_id);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This scholarship type does not exist';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  
    // Delete the scholarship type
    $stmt = $conn->prepare('DELETE FROM scholarship_types WHERE scholarship_type_id = ?');
    $stmt->bind_param('s', $scholarship_type_id);
  
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Scholarship type deleted successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error deleting scholarship type: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }  

  public function hide_scholarship_archive() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    // Extract scholarship type ID and archive status
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');
    $archive = htmlspecialchars($_GET['archive'] ?? ''); // Expecting 'true' or 'false'

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    if (empty($scholarship_type_id)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Validate archive value
    if ($archive !== '' && $archive !== 'hide') {
      $response['status'] = 'error';
      $response['message'] = 'Invalid archive value. It must be either "true" or "false".';
      echo json_encode($response);
      return;
    }

    // Update the archive status in the scholarship_types table for the specified scholarship_type_id
    $stmt = $conn->prepare('UPDATE scholarship_types SET archive = ? WHERE scholarship_type_id = ?');
    $stmt->bind_param('ss', $archive, $scholarship_type_id); // Assuming scholarship_type_id is an integer

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Archive status updated successfully in the scholarship_types table';
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating archive status in the scholarship_types table: ' . $conn->error;
    }

    // Update the archive status in the types table for all records based on scholarship_type_id
    $stmt = $conn->prepare('UPDATE types SET archive = ? WHERE scholarship_type_id = ?');
    $stmt->bind_param('si', $archive, $scholarship_type_id);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Archive status updated successfully in the types table';
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating archive status in the types table: ' . $conn->error;
    }

    $stmt->close();
    echo json_encode($response);
  }     

  // Type
  public function add_type(){
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    $data = json_decode(file_get_contents("php://input"), true);
    $type_id = bin2hex(random_bytes(16));
    $scholarship_type_id = htmlspecialchars($data['scholarship_type_id'] ?? '');
    $type = htmlspecialchars($data['type'] ?? '');
    $description = htmlspecialchars($data['description'] ?? '');
    $eligibility = htmlspecialchars($data['eligibility'] ?? '');
    $created_at = date('Y-m-d H:i:s');

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    // Validate required fields
    if (empty($scholarship_type_id)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship type ID cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($type)) {
      $response['status'] = 'error';
      $response['message'] = 'Type cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($description)) {
      $response['status'] = 'error';
      $response['message'] = 'Description cannot be empty';
      echo json_encode($response);
      return;
    }

    if (empty($eligibility)) {
      $response['status'] = 'error';
      $response['message'] = 'Eligibility cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if the type already exists under the same scholarship_type_id
    $stmt = $conn->prepare("SELECT type FROM types WHERE scholarship_type_id = ? AND type = ?");
    $stmt->bind_param("ss", $scholarship_type_id, $type);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This type already exists for the given scholarship type';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Insert data into the 'types' table
    $stmt = $conn->prepare('INSERT INTO types (type_id, scholarship_type_id, type, description, eligibility, created_at) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('ssssss', $type_id, $scholarship_type_id, $type, $description, $eligibility, $created_at);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Type added successfully';

      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'type',          
        'added a type',      
        'Added new type: ' . $type 
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error adding type: ' . $conn->error;
    }

    $stmt->close();
    echo json_encode($response);
  }

  public function get_type() {
    global $conn;
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get the current page and the number of records per page from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
  
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
  
    // Fetch types with pagination
    $stmt = $conn->prepare("SELECT type_id, type, description, eligibility, archive, created_at FROM types LIMIT ?, ?");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Get total number of records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM types");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $types = array();
  
      while ($row = $result->fetch_assoc()) {
        $types[] = array(
          'type_id' => $row['type_id'],
          'type' => $row['type'],
          'description' => $row['description'],
          'eligibility' => $row['eligibility'],
          'archive' => $row['archive'],
          'created_at' => $row['created_at']
        );
      }
  
      $response['status'] = 'success';
      $response['data'] = $types;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No types found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }  

  public function update_type() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $data = json_decode(file_get_contents("php://input"), true);
    $type_id = htmlspecialchars($_GET['tid'] ?? '');
    $archive = htmlspecialchars($data['archive'] ?? '');
    $type = htmlspecialchars($data['type'] ?? '');
    $description = htmlspecialchars($data['description'] ?? '');
    $eligibility = htmlspecialchars($data['eligibility'] ?? '');
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    if (empty($type)) {
      $response['status'] = 'error';
      $response['message'] = 'Type cannot be empty';
      echo json_encode($response);
      return;
    }
  
    if (empty($description)) {
      $response['status'] = 'error';
      $response['message'] = 'Description cannot be empty';
      echo json_encode($response);
      return;
    }
  
    if (empty($eligibility)) {
      $response['status'] = 'error';
      $response['message'] = 'Eligibility cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Update data in the 'types' table
    $stmt = $conn->prepare('UPDATE types SET archive = ?, type = ?, description = ?, eligibility = ? WHERE type_id = ?');
    $stmt->bind_param('sssss', $archive, $type, $description, $eligibility, $type_id);
  
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Type updated successfully';

      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'type',          
        'updated a type',      
        'Updated the type: ' . $type 
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating type: ' . $conn->error;
    }
  
    $stmt->close();
    echo json_encode($response);
  }  

  // Scholar Category
  public function get_scholarship_type_by_category() {
    global $conn;
    $response = array();
  
    // Retrieve the request data
    $category = htmlspecialchars($_GET['category'] ?? '');
  
    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user is authorized (admin or any authorized role)
    if ($security_response['role'] !== 'admin' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Validate category input
    if (empty($category)) {
      $response['status'] = 'error';
      $response['message'] = 'Category cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Fetch scholarship types based on the category (internal or external)
    $stmt = $conn->prepare("SELECT * FROM scholarship_types WHERE category = ?");
    $stmt->bind_param("s", $category);
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows > 0) {
      $scholarship_types = array();
  
      while ($row = $result->fetch_assoc()) {
        $scholarship_types[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $scholarship_types;
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No scholarship types found for the selected category';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }  

  // Account Approval
  public function get_users() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get the current page and the number of records per page from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
  
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
  
    // Fetch users with pagination
    $stmt = $conn->prepare("SELECT profile, user_id, student_number, first_name, last_name, email, role, joined_at 
                            FROM users 
                            WHERE role = 'pending'
                            LIMIT ?, ?");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Get total number of records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM users WHERE role = 'pending'");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $users = array();
  
      while ($row = $result->fetch_assoc()) {
        $users[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $users;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No users found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }  

  public function search_users() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get the search query, page, and limit from the request
    $search_query = isset($_GET['query']) ? '%' . $_GET['query'] . '%' : '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
  
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
  
    // Prepare the search SQL query
    $stmt = $conn->prepare("SELECT profile, user_id, student_number, first_name, last_name, email, role, joined_at 
                            FROM users 
                            WHERE role = 'pending' AND (student_number LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)
                            LIMIT ?, ?");
    $stmt->bind_param("ssssii", $search_query, $search_query, $search_query, $search_query, $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Get total number of matching records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM users 
                                  WHERE role = 'pending' 
                                  AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)");
    $total_stmt->bind_param("sss", $search_query, $search_query, $search_query);
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $users = array();
  
      while ($row = $result->fetch_assoc()) {
        $users[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $users;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No users found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }  

  public function update_user_role() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
    $email = new SendEmail();
    
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
    
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
    
    // Get the user ID and new role from the request
    $user_id = isset($_GET['uid']) ? trim($_GET['uid']) : '';
    $new_role = isset($_GET['role']) ? trim($_GET['role']) : '';
  
    if(empty($new_role)){
      $response['status'] = 'error';
      $response['message'] = 'Role cannot be empty';
      echo json_encode($response);
      return;
    }
    
    // Validate the new role
    $allowed_roles = ['student', 'admin', 'dean', 'adviser'];
    if (!in_array($new_role, $allowed_roles)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid role';
      echo json_encode($response);
      return;
    }
    
    // Check if the user ID is valid
    if ($user_id === null || $user_id <= 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid user ID.';
      echo json_encode($response);
      return;
    }
  
    // Check if the user ID exists
    $stmt = $conn->prepare("SELECT user_id, first_name, last_name, email FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user does not exist';
      echo json_encode($response);
      return;
    }
  
    $user = $result->fetch_assoc();
    $first_name = $user['first_name'];
    $last_name = $user['last_name'];
    $recipientEmail = $user['email'];
  
    $stmt->close();
    
    // Update the user's role in the database
    $stmt = $conn->prepare("UPDATE users SET role = ? WHERE user_id = ?");
    $stmt->bind_param("si", $new_role, $user_id);
    
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'User role updated successfully';
  
      // Send email notification to user
      $senderName = 'UPHSD-Calamba Scholarship';
      $senderEmail = 'razonmarknicholas.cdlb@gmail.com';
      $subject = 'Account Role Update';
      $body = "
        <h1>Account Role Update</h1>
        <p>Hello $first_name $last_name,</p>
        <p>Your account role has been updated to: <strong>$new_role</strong>.</p>
        <p>Thank you for being a part of our community!</p>
      ";
  
      // Send the email
      $emailResponse = $email->sendMail($senderName, $senderEmail, $recipientEmail, $subject, $body);
      $response['email_status'] = $emailResponse;
  
      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'users',          
        'update a user role',      
        'Updated the role of user to: ' . $new_role 
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to update user role. Please try again.';
    }
  
    $stmt->close();
    echo json_encode($response);
  }    

  public function delete_user() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    // Extract user ID from the request
    $user_id = htmlspecialchars($_GET['uid'] ?? '');

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if the user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user does not exist';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Delete the user
    $stmt = $conn->prepare('DELETE FROM users WHERE user_id = ?');
    $stmt->bind_param('s', $user_id);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'User deleted successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error deleting user: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  } 

  // Active Accounts
  public function get_active_users() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get the current page and the number of records per page from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
  
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
  
    // Fetch users with pagination
    $stmt = $conn->prepare("SELECT profile, user_id, student_number, first_name, last_name, email, role, status, last_login, joined_at 
                            FROM users 
                            WHERE role != 'pending'
                            LIMIT ?, ?");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Get total number of records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM users WHERE role = 'pending'");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $users = array();
  
      while ($row = $result->fetch_assoc()) {
        $users[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $users;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No users found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }

  public function search_active_users() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get the search query, page, and limit from the request
    $search_query = isset($_GET['query']) ? '%' . $_GET['query'] . '%' : '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
  
    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;
  
    // Prepare the search SQL query
    $stmt = $conn->prepare("SELECT profile, user_id, student_number, first_name, last_name, email, role, status, last_login, joined_at 
                            FROM users 
                            WHERE role != 'pending' AND (student_number LIKE ? OR first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)
                            LIMIT ?, ?");
    $stmt->bind_param("ssssii", $search_query, $search_query, $search_query, $search_query, $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Get total number of matching records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM users 
                                  WHERE role = 'pending' 
                                  AND (first_name LIKE ? OR last_name LIKE ? OR email LIKE ?)");
    $total_stmt->bind_param("sss", $search_query, $search_query, $search_query);
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $users = array();
  
      while ($row = $result->fetch_assoc()) {
        $users[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $users;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No users found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  } 

  public function update_active_users() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    // Extract user ID and status from the request
    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $status = htmlspecialchars($_GET['status'] ?? '');

    // Create a new instance for the security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    if ($status !== 'deactivated' && $status !== '') {
      $response['status'] = 'error';
      $response['message'] = 'Invalid status provided. It must be either "deactivated" or blank.';
      echo json_encode($response);
      return;
    }

    // Check if the user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user does not exist';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Update the user's status based on the provided value
    $stmt = $conn->prepare('UPDATE users SET status = ? WHERE user_id = ?');
    $stmt->bind_param('ss', $status, $user_id);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = $status === 'deactivated' ? 'User deactivated successfully' : 'User activated successfully';
      
      // Log the activity
      $activityLogger = new ActivityLogger($conn);
      $logResponse = $activityLogger->logActivity(
        $security_response['user_id'],         
        'user status',          
        'updated a user status',      
        'Updated the user status: ' . $status
      );
      
      // Handle the logging response
      if ($logResponse['status'] === 'error') {
        $response['activity_log'] = $logResponse['message'];
      } else {
        $response['activity_log'] = 'Activity logged successfully';
      }
      
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error updating user status: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  } 

  // Applications
  public function get_applications() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $offset = ($page - 1) * $records_per_page;
  
    $stmt = $conn->prepare("
      SELECT a.application_id, a.scholarship_type_id, a.type_id, a.status, a.created_at, 
             u.user_id, u.profile, u.student_number, u.email, u.first_name, u.middle_name, u.last_name, 
             t.type, f.program, f.year_level, f.general_weighted_average, f.contact_number, f.honors_received
      FROM applications a
      LEFT JOIN users u ON a.user_id = u.user_id
      LEFT JOIN types t ON a.type_id = t.type_id
      LEFT JOIN forms f ON a.scholarship_type_id = f.scholarship_type_id 
                          AND a.type_id = f.type_id 
                          AND a.user_id = f.user_id
      WHERE a.status = 'pending'
      LIMIT ?, ?
    ");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM applications WHERE status = 'pending'");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $scholars = array();
  
      while ($row = $result->fetch_assoc()) {
        $scholar = array(
          'user_id' => $row['user_id'] ?? '',
          'application_id' => $row['application_id'],
          'scholarship_type_id' => $row['scholarship_type_id'],
          'type_id' => $row['type_id'],
          'form_type' => $row['type'] ?? '',
          'status' => $row['status'],
          'created_at' => date('F j, Y g:i A', strtotime($row['created_at'])),
          'profile' => $row['profile'] ?? '',
          'student_number' => $row['student_number'] ?? '',
          'email' => $row['email'] ?? '',
          'first_name' => $row['first_name'] ?? '',
          'middle_name' => $row['middle_name'] ?? '',
          'last_name' => $row['last_name'] ?? '',
          'contact_number' => $row['contact_number'] ?? '',
          'honors_received' => $row['honors_received'] ?? '',
          'course' => $row['program'] ?? '',
          'year_level' => $row['year_level'] ?? '',
          'general_weighted_average' => is_numeric($row['general_weighted_average']) ? $row['general_weighted_average'] : ''
        );
  
        $scholars[] = $scholar;
      }
  
      $response['status'] = 'success';
      $response['data'] = $scholars;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No applications found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }         

  public function search_applications() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Handle search, pagination, and limit defaults
    $search_query = isset($_GET['query']) ? '%' . $conn->real_escape_string($_GET['query']) . '%' : '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $offset = ($page - 1) * $records_per_page;
  
    // Prepare main query with necessary joins and WHERE clause
    $stmt = $conn->prepare("
      SELECT a.application_id, a.scholarship_type_id, a.type_id, a.status, a.created_at, 
             u.user_id, u.profile, u.student_number, u.email, u.first_name, u.middle_name, u.last_name, 
             t.type, f.program, f.year_level, f.general_weighted_average, f.contact_number, f.honors_received
      FROM applications a
      LEFT JOIN users u ON a.user_id = u.user_id
      LEFT JOIN types t ON a.type_id = t.type_id
      LEFT JOIN forms f ON a.scholarship_type_id = f.scholarship_type_id 
                          AND a.type_id = f.type_id 
                          AND a.user_id = f.user_id
      WHERE a.status = 'pending'
      AND (u.student_number LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)
      LIMIT ?, ?
    ");
  
    $stmt->bind_param("sssssi", $search_query, $search_query, $search_query, $search_query, $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Adjust total count query to consider the search query
    $total_stmt = $conn->prepare("
      SELECT COUNT(*) as total 
      FROM applications a 
      LEFT JOIN users u ON a.user_id = u.user_id 
      WHERE a.status = 'pending' 
      AND (u.student_number LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)
    ");
    $total_stmt->bind_param("ssss", $search_query, $search_query, $search_query, $search_query);
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    // Fetch data and build the response
    if ($result->num_rows > 0) {
      $scholars = array();
  
      while ($row = $result->fetch_assoc()) {
        $scholars[] = array(
          'user_id' => $row['user_id'] ?? '',
          'application_id' => $row['application_id'],
          'scholarship_type_id' => $row['scholarship_type_id'],
          'type_id' => $row['type_id'],
          'form_type' => $row['type'] ?? '',
          'status' => $row['status'],
          'created_at' => date('F j, Y g:i A', strtotime($row['created_at'])),
          'profile' => $row['profile'] ?? '',
          'student_number' => $row['student_number'] ?? '',
          'email' => $row['email'] ?? '',
          'first_name' => $row['first_name'] ?? '',
          'middle_name' => $row['middle_name'] ?? '',
          'last_name' => $row['last_name'] ?? '',
          'contact_number' => $row['contact_number'] ?? '',
          'honors_received' => $row['honors_received'] ?? '',
          'course' => $row['program'] ?? '',
          'year_level' => $row['year_level'] ?? '',
          'general_weighted_average' => is_numeric($row['general_weighted_average']) ? $row['general_weighted_average'] : ''
        );
      }
  
      $response['status'] = 'success';
      $response['data'] = $scholars;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No applications found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }    

  public function update_application() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
    $email = new SendEmail();
    
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
    
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
    
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
    
    // Get application ID and new status from the request
    $application_id = isset($_GET['aid']) ? $_GET['aid'] : null;
    $new_status = isset($_GET['status']) ? $_GET['status'] : null;
    
    // Validate inputs
    if (is_null($application_id) || !in_array($new_status, ['accepted', 'declined'])) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid application ID or status']);
      return;
    }
    
    // Get user details based on application_id
    $stmt = $conn->prepare("SELECT u.user_id, u.first_name, u.middle_name, u.last_name, u.email
                            FROM applications a
                            JOIN users u ON a.user_id = u.user_id
                            WHERE a.application_id = ?");
    $stmt->bind_param("s", $application_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
      // Fetch user details
      $user = $result->fetch_assoc();
      $user_id = $user['user_id'];
      $first_name = $user['first_name'];
      $middle_name = $user['middle_name'];
      $last_name = $user['last_name'];
      $recipientEmail = $user['email'];
    
      // Update the application status
      $stmt = $conn->prepare("UPDATE applications SET status = ? WHERE application_id = ? AND status = 'pending'");
      $stmt->bind_param("ss", $new_status, $application_id);
    
      if ($stmt->execute()) {
        if ($stmt->affected_rows > 0) {
          $response['status'] = 'success';
          $response['message'] = 'Application status updated successfully';
    
          // Send email confirmation
          $senderName = 'UPHSD-Calamba Scholarship';
          $senderEmail = 'razonmarknicholas.cdlb@gmail.com';
          $subject = 'Application Status Update';
          $body = "
            <h1>Application Status Update</h1>
            <p>Hello $first_name $middle_name $last_name,</p>
            <p>Your application has been updated to: <strong>$new_status</strong>.</p>
            <p>Thank you for your attention.</p>
          ";
    
          // Send the email
          $response['email_status'] = $email->sendMail($senderName, $senderEmail, $recipientEmail, $subject, $body);
          
          // Log the activity using the retrieved user_id
          $activityLogger = new ActivityLogger($conn);
          $logResponse = $activityLogger->logActivity(
            $security_response['user_id'],           
            'applications',                      
            'updated an application',                  
            'Updated the application of: ' . $application_id . ' to ' . $new_status
          );
    
          // Handle the logging response
          if ($logResponse['status'] === 'error') {
            $response['activity_log'] = $logResponse['message'];
          } else {
            $response['activity_log'] = 'Activity logged successfully';
          }
        } else {
          $response['status'] = 'error';
          $response['message'] = 'Application not found or already updated';
        }
      } else {
        $response['status'] = 'error';
        $response['message'] = 'Failed to update application status';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No user found for this application';
    }
  
    $stmt->close();
    echo json_encode($response);
  }   
  
  public function delete_application() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get application ID from the request
    $application_id = isset($_GET['aid']) ? $_GET['aid'] : null; 
  
    // Validate inputs
    if (is_null($application_id)) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid application ID']);
      return;
    }
  
    // Delete the application
    $stmt = $conn->prepare("DELETE FROM applications WHERE application_id = ?");
    $stmt->bind_param("s", $application_id);
  
    if ($stmt->execute()) {
      if ($stmt->affected_rows > 0) {
        $response['status'] = 'success';
        $response['message'] = 'Application deleted successfully';
      } else {
        $response['status'] = 'error';
        $response['message'] = 'Application not found';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to delete application';
    }
  
    $stmt->close();
    echo json_encode($response);
  }  

  // Scholars
  public function get_scholars() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $offset = ($page - 1) * $records_per_page;
  
    $stmt = $conn->prepare("
      SELECT a.application_id, a.scholarship_type_id, a.type_id, a.status, a.created_at, 
             u.user_id, u.profile, u.student_number, u.email, u.first_name, u.middle_name, u.last_name, 
             t.type, f.program, f.year_level, f.general_weighted_average, f.contact_number, f.honors_received
      FROM applications a
      LEFT JOIN users u ON a.user_id = u.user_id
      LEFT JOIN types t ON a.type_id = t.type_id
      LEFT JOIN forms f ON a.scholarship_type_id = f.scholarship_type_id 
                          AND a.type_id = f.type_id 
                          AND a.user_id = f.user_id
      WHERE a.status = 'accepted'
      LIMIT ?, ?
    ");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM applications WHERE status = 'accepted'");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $scholars = array();
  
      while ($row = $result->fetch_assoc()) {
        $scholar = array(
          'user_id' => $row['user_id'] ?? '',
          'application_id' => $row['application_id'],
          'scholarship_type_id' => $row['scholarship_type_id'],
          'type_id' => $row['type_id'],
          'form_type' => $row['type'] ?? '',
          'status' => $row['status'],
          'created_at' => date('F j, Y g:i A', strtotime($row['created_at'])),
          'profile' => $row['profile'] ?? '',
          'student_number' => $row['student_number'] ?? '',
          'email' => $row['email'] ?? '',
          'first_name' => $row['first_name'] ?? '',
          'middle_name' => $row['middle_name'] ?? '',
          'last_name' => $row['last_name'] ?? '',
          'contact_number' => $row['contact_number'] ?? '',
          'honors_received' => $row['honors_received'] ?? '',
          'course' => $row['program'] ?? '',
          'year_level' => $row['year_level'] ?? '',
          'general_weighted_average' => is_numeric($row['general_weighted_average']) ? $row['general_weighted_average'] : ''
        );
  
        $scholars[] = $scholar;
      }
  
      $response['status'] = 'success';
      $response['data'] = $scholars;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No applications found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  } 

  public function search_scholars() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Handle search, pagination, and limit defaults
    $search_query = isset($_GET['query']) ? '%' . $conn->real_escape_string($_GET['query']) . '%' : '';
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
    $offset = ($page - 1) * $records_per_page;
  
    // Prepare main query with necessary joins and WHERE clause
    $stmt = $conn->prepare("
      SELECT a.application_id, a.scholarship_type_id, a.type_id, a.status, a.created_at, 
             u.user_id, u.profile, u.student_number, u.email, u.first_name, u.middle_name, u.last_name, 
             t.type, f.program, f.year_level, f.general_weighted_average, f.contact_number, f.honors_received
      FROM applications a
      LEFT JOIN users u ON a.user_id = u.user_id
      LEFT JOIN types t ON a.type_id = t.type_id
      LEFT JOIN forms f ON a.scholarship_type_id = f.scholarship_type_id 
                          AND a.type_id = f.type_id 
                          AND a.user_id = f.user_id
      WHERE a.status = 'accepted'
      AND (u.student_number LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)
      LIMIT ?, ?
    ");
  
    $stmt->bind_param("sssssi", $search_query, $search_query, $search_query, $search_query, $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    // Adjust total count query to consider the search query
    $total_stmt = $conn->prepare("
      SELECT COUNT(*) as total 
      FROM applications a 
      LEFT JOIN users u ON a.user_id = u.user_id 
      WHERE a.status = 'accepted' 
      AND (u.student_number LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ? OR u.email LIKE ?)
    ");
    $total_stmt->bind_param("ssss", $search_query, $search_query, $search_query, $search_query);
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    // Fetch data and build the response
    if ($result->num_rows > 0) {
      $scholars = array();
  
      while ($row = $result->fetch_assoc()) {
        $scholars[] = array(
          'user_id' => $row['user_id'] ?? '',
          'application_id' => $row['application_id'],
          'scholarship_type_id' => $row['scholarship_type_id'],
          'type_id' => $row['type_id'],
          'form_type' => $row['type'] ?? '',
          'status' => $row['status'],
          'created_at' => date('F j, Y g:i A', strtotime($row['created_at'])),
          'profile' => $row['profile'] ?? '',
          'student_number' => $row['student_number'] ?? '',
          'email' => $row['email'] ?? '',
          'first_name' => $row['first_name'] ?? '',
          'middle_name' => $row['middle_name'] ?? '',
          'last_name' => $row['last_name'] ?? '',
          'contact_number' => $row['contact_number'] ?? '',
          'honors_received' => $row['honors_received'] ?? '',
          'course' => $row['program'] ?? '',
          'year_level' => $row['year_level'] ?? '',
          'general_weighted_average' => is_numeric($row['general_weighted_average']) ? $row['general_weighted_average'] : ''
        );
      }
  
      $response['status'] = 'success';
      $response['data'] = $scholars;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No applications found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  } 
  
  public function delete_scholar() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
  
    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Get application ID from the request
    $application_id = isset($_GET['aid']) ? $_GET['aid'] : null; 
  
    // Validate inputs
    if (is_null($application_id)) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid application ID']);
      return;
    }
  
    // Delete the application
    $stmt = $conn->prepare("DELETE FROM applications WHERE application_id = ?");
    $stmt->bind_param("s", $application_id);
  
    if ($stmt->execute()) {
      if ($stmt->affected_rows > 0) {
        $response['status'] = 'success';
        $response['message'] = 'Application deleted successfully';
      } else {
        $response['status'] = 'error';
        $response['message'] = 'Application not found';
      }
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to delete application';
    }
  
    $stmt->close();
    echo json_encode($response);
  }   

  // Accounts
  public function get_user_accounts() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
        echo json_encode($security_response);
        return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
        echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
        return;
    }

    // Get the current page and the number of records per page from the request
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $records_per_page = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;

    // Calculate the starting record for the query
    $offset = ($page - 1) * $records_per_page;

    // Fetch users with pagination where role is NOT 'pending'
    $stmt = $conn->prepare("SELECT user_id, first_name, last_name, email, role, joined_at 
                            FROM users 
                            WHERE role != 'pending'
                            LIMIT ?, ?");
    $stmt->bind_param("ii", $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();

    // Get total number of records for pagination info
    $total_stmt = $conn->prepare("SELECT COUNT(*) as total FROM users WHERE role != 'pending'");
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];

    if ($result->num_rows > 0) {
        $users = array();

        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }

        $response['status'] = 'success';
        $response['data'] = $users;
        $response['pagination'] = array(
            'current_page' => $page,
            'records_per_page' => $records_per_page,
            'total_records' => $total_records,
            'total_pages' => ceil($total_records / $records_per_page)
        );
    } else {
        $response['status'] = 'error';
        $response['message'] = 'No users found';
    }

    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }

  public function delete_user_accounts() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();

    // Extract user ID from the request
    $user_id = htmlspecialchars($_GET['uid'] ?? '');

    // Create a new instance for security key
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    // Check if the user's role is 'admin'
    if ($security_response['role'] !== 'admin') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Check if the user exists
    $stmt = $conn->prepare("SELECT user_id FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
      $stmt->close();
      $response['status'] = 'error';
      $response['message'] = 'This user does not exist';
      echo json_encode($response);
      return;
    }

    $stmt->close();

    // Delete the user
    $stmt = $conn->prepare('DELETE FROM users WHERE user_id = ?');
    $stmt->bind_param('s', $user_id);

    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'User deleted successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error deleting user: ' . $conn->error;
      echo json_encode($response);
      return;
    }
  }
}
?>