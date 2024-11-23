<?php

class StudentController{
  public function get_account_by_id() {
    global $conn;
    $response = array();

    // Variables
    $user_id = htmlspecialchars($_GET['uid'] ?? '');

    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    // Validate input
    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Fetch user data based on the user_id
    $stmt = $conn->prepare("SELECT 
                              user_id,
                              student_number,
                              profile,
                              first_name,
                              middle_name,
                              last_name,
                              date_of_birth,
                              place_of_birth
                            FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
      $user_data = array();

      while ($row = $result->fetch_assoc()) {
        $user_data[] = $row;
      }

      $response['status'] = 'success';
      $response['user'] = $user_data;
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No user found';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }

  public function update_account() {
    global $conn;
    $response = array();

    // Variables
    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $student_number = htmlspecialchars($data['student_number'] ?? '');
    $first_name = htmlspecialchars($data['first_name'] ?? '');
    $middle_name = htmlspecialchars($data['middle_name'] ?? '');
    $last_name = htmlspecialchars($data['last_name'] ?? '');
    $date_of_birth = htmlspecialchars($data['date_of_birth'] ?? '');
    $place_of_birth = htmlspecialchars($data['place_of_birth'] ?? '');

    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();

    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }

    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    // Validate input
    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }
    
    if (empty($first_name)) {
      $response['status'] = 'error';
      $response['message'] = 'First name cannot be empty';
      echo json_encode($response);
      return;
    }
    
    if (empty($last_name)) {
      $response['status'] = 'error';
      $response['message'] = 'Last name cannot be empty';
      echo json_encode($response);
      return;
    }

    // Update user data
    $stmt = $conn->prepare("UPDATE users SET 
                              student_number = ?,
                              first_name = ?, 
                              middle_name = ?, 
                              last_name = ?, 
                              date_of_birth = ?, 
                              place_of_birth = ? 
                            WHERE user_id = ?");
    $stmt->bind_param(
      "sssssss", 
      $student_number, 
      $first_name, 
      $middle_name, 
      $last_name, 
      $date_of_birth, 
      $place_of_birth, 
      $user_id
    );
    
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'User account updated successfully';
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to update user account';
    }

    echo json_encode($response);
    $stmt->close();
  }

  public function get_applications() {
    global $conn;
    $response = array();
  
    // Variables
    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $search_query = htmlspecialchars($_GET['search'] ?? '');
    $page = isset($_GET['page']) ? intval($_GET['page']) : 1;  // Default to page 1
    $records_per_page = isset($_GET['limit']) ? intval($_GET['limit']) : 10;  // Default to 10 records per page
    $offset = ($page - 1) * $records_per_page;  // Calculate the offset for the SQL query
  
    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Validate input
    if (empty($user_id)) {
      $response['status'] = 'error';
      $response['message'] = 'User ID cannot be empty';
      echo json_encode($response);
      return;
    }
  
    // Get total records count for pagination
    $count_query_str = "SELECT COUNT(*) FROM forms WHERE user_id = ?";
    if (!empty($search_query)) {
      $count_query_str .= " AND (first_name LIKE ? OR last_name LIKE ? OR email_address LIKE ?)";
    }
    $count_query = $conn->prepare($count_query_str);
    if (!empty($search_query)) {
      $search_query_param = "%$search_query%";
      $count_query->bind_param("ssss", $user_id, $search_query_param, $search_query_param, $search_query_param);
    } else {
      $count_query->bind_param("s", $user_id);
    }
    $count_query->execute();
    $count_query->bind_result($total_records);
    $count_query->fetch();
    $count_query->close();
  
    // Fetch user data with pagination
    $stmt_str = "SELECT 
                  forms.*, 
                  scholarship_types.scholarship_type, 
                  types.type, 
                  applications.status
                FROM 
                  forms
                JOIN 
                  scholarship_types ON forms.scholarship_type_id = scholarship_types.scholarship_type_id
                JOIN 
                  types ON forms.type_id = types.type_id
                JOIN 
                  applications ON forms.scholarship_type_id = applications.scholarship_type_id 
                  AND forms.type_id = applications.type_id
                  AND forms.user_id = applications.user_id
                WHERE 
                  forms.user_id = ?";
  
    if (!empty($search_query)) {
      $stmt_str .= " AND (first_name LIKE ? OR last_name LIKE ? OR email_address LIKE ?)";
    }
  
    $stmt_str .= " ORDER BY forms.created_at DESC LIMIT ?, ?";
  
    $stmt = $conn->prepare($stmt_str);
  
    if (!empty($search_query)) {
      $stmt->bind_param("ssssi", $user_id, $search_query_param, $search_query_param, $search_query_param, $offset, $records_per_page);
    } else {
      $stmt->bind_param("sii", $user_id, $offset, $records_per_page);
    }
  
    $stmt->execute();
    $result = $stmt->get_result();
  
    if ($result->num_rows > 0) {
      $applications = array();
  
      while ($row = $result->fetch_assoc()) {
        $applications[] = $row;
      }
  
      // Pagination response
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
  
      $response['status'] = 'success';
      $response['data'] = $applications;
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No applications found';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }    

  public function get_scholarship_types() {
    global $conn;
    $response = array();

    // Variables
    $filter = htmlspecialchars($_GET['filter'] ?? 'internal');

    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    // Validate input
    if (empty($filter)) {
      $response['status'] = 'error';
      $response['message'] = 'Filter cannot be empty';
      echo json_encode($response);
      return;
    }

    // Fetch user data based on the user_id
    $stmt = $conn->prepare("SELECT 
                              scholarship_type_id,
                              scholarship_type,
                              category,
                              description,
                              eligibility,
                              archive,
                              created_at
                            FROM scholarship_types WHERE category = ?");
    $stmt->bind_param("s", $filter);
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
      $response['message'] = 'No scholarship types found';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }

  public function get_type_by_stid() {
    global $conn;
    $response = array();

    // Variables
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');

    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }

    // Validate input
    if (empty($scholarship_type_id)) {
      $response['status'] = 'error';
      $response['message'] = 'Scholarship Type ID cannot be empty';
      echo json_encode($response);
      return;
    }

    // Fetch user data based on the user_id
    $stmt = $conn->prepare("SELECT 
                              *
                            FROM types WHERE scholarship_type_id = ? AND archive != 'hide'");
    $stmt->bind_param("s", $scholarship_type_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
      $types = array();

      while ($row = $result->fetch_assoc()) {
        $types[] = $row;
      }

      $response['status'] = 'success';
      $response['data'] = $types;
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No types found';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }

  // Application forms
  public function insert_entrance_application() {
    global $conn;
    date_default_timezone_set('Asia/Manila');
    $response = array();
    
    // Variables
    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');
    $type_id = htmlspecialchars($_GET['tid'] ?? '');
    $first_name = htmlspecialchars($data['first_name'] ?? '');
    $middle_name = htmlspecialchars($data['middle_name'] ?? '');
    $last_name = htmlspecialchars($data['last_name'] ?? '');
    $suffix = htmlspecialchars($data['suffix'] ?? '');
    $academic_year = htmlspecialchars($data['academic_year'] ?? '');
    $year_level = htmlspecialchars($data['year_level'] ?? '');
    $semester = htmlspecialchars($data['semester'] ?? '');
    $program = htmlspecialchars($data['program'] ?? '');
    $email_address = htmlspecialchars($data['email_address'] ?? '');
    $contact_number = htmlspecialchars($data['contact_number'] ?? '');
    $honors_received = htmlspecialchars($data['honors_received'] ?? '');
    $general_weighted_average = htmlspecialchars($data['general_weighted_average'] ?? '');
    
    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
    
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
    
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
    
    // Validation checks
    $required_fields = [
      'uid' => $user_id,
      'stid' => $scholarship_type_id,
      'tid' => $type_id,
      'first_name' => $first_name,
      'middle_name' => $middle_name,
      'last_name' => $last_name,
      'academic_year' => $academic_year,
      'semester' => $semester,
      'program' => $program,
      'email_address' => $email_address,
      'contact_number' => $contact_number,
      'honors_received' => $honors_received,
      'general_weighted_average' => $general_weighted_average
    ];
    
    foreach ($required_fields as $field => $value) {
      if (empty($value)) {
        $response['status'] = 'error';
        $response['message'] = ucfirst(str_replace('_', ' ', $field)) . ' cannot be empty';
        echo json_encode($response);
        return;
      }
    }
  
    // Check if user_id exists in the users table
    $check_user_id = $conn->prepare("SELECT user_id, student_number, first_name, middle_name, last_name, email FROM users WHERE user_id = ?");
    $check_user_id->bind_param("s", $user_id);
    $check_user_id->execute();
    $check_user_id->store_result();
    
    if ($check_user_id->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid user ID';
      echo json_encode($response);
      $check_user_id->close();
      return;
    }
  
    // Fetch user data and validate that fields are not empty or null
    $check_user_id->bind_result($db_user_id, $student_number, $db_first_name, $db_middle_name, $db_last_name, $db_email);
    $check_user_id->fetch();
    
    if (empty($student_number) || empty($db_first_name) || empty($db_middle_name) || empty($db_last_name) || empty($db_email)) {
      $response['status'] = 'error';
      $response['message'] = 'User information is incomplete. Application cannot be submitted.';
      echo json_encode($response);
      $check_user_id->close();
      return;
    }
  
    $check_user_id->close();
  
    // Check if scholarship_type_id exists in the scholarship_types table
    $check_scholarship_type = $conn->prepare("SELECT scholarship_type_id FROM scholarship_types WHERE scholarship_type_id = ?");
    $check_scholarship_type->bind_param("s", $scholarship_type_id);
    $check_scholarship_type->execute();
    $check_scholarship_type->store_result();
  
    if ($check_scholarship_type->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid scholarship type ID';
      echo json_encode($response);
      $check_scholarship_type->close();
      return;
    }
    $check_scholarship_type->close();
  
    // Check if type_id exists in the types table and if the archive field allows submission
    $check_type_id = $conn->prepare("SELECT type_id, archive FROM types WHERE type_id = ?");
    $check_type_id->bind_param("s", $type_id);
    $check_type_id->execute();
    $check_type_id->store_result();
    $check_type_id->bind_result($db_type_id, $archive);
  
    if ($check_type_id->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid type ID';
      echo json_encode($response);
      $check_type_id->close();
      return;
    }
  
    $check_type_id->fetch();
  
    if (!empty($archive) || $archive === 'hide') {
      $response['status'] = 'error';
      $response['message'] = 'Application submission is closed';
      echo json_encode($response);
      $check_type_id->close();
      return;
    }
  
    $check_type_id->close();
    
    // Insert data into `forms`
    $stmt = $conn->prepare("INSERT INTO forms (
                              user_id,
                              scholarship_type_id,
                              type_id,
                              first_name,
                              middle_name,
                              last_name,
                              suffix,
                              academic_year,
                              year_level,
                              semester,
                              program,
                              email_address,
                              contact_number,
                              honors_received,
                              general_weighted_average,
                              created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())");
  
    $stmt->bind_param(
      "ssssssssssssssd", 
      $user_id,
      $scholarship_type_id,
      $type_id,
      $first_name,
      $middle_name,
      $last_name,
      $suffix,
      $academic_year,
      $year_level,
      $semester,
      $program,
      $email_address,
      $contact_number,
      $honors_received,
      $general_weighted_average
    );
    
    if ($stmt->execute()) {
      // Get the last inserted form ID (application_id)
      $application_id = bin2hex(random_bytes(16));
      $status = 'pending';
      $created_at = date('Y-m-d H:i:s'); // Get current timestamp
      $stmt_app = $conn->prepare("INSERT INTO applications (
                                   application_id,
                                   user_id,
                                   scholarship_type_id,
                                   type_id,
                                   status,
                                   created_at
                                 ) VALUES (?, ?, ?, ?, ?, ?)");
      
      $stmt_app->bind_param("ssssss", $application_id, $user_id, $scholarship_type_id, $type_id, $status, $created_at);
      
      if ($stmt_app->execute()) {
        $response['status'] = 'success';
        $response['message'] = 'Entrance application and application record submitted successfully';
        echo json_encode($response);
      } else {
        $response['status'] = 'error';
        $response['message'] = 'Failed to insert into applications table';
        echo json_encode($response);
      }
      
      $stmt_app->close();
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to submit entrance application';
      echo json_encode($response);
      return;
    }
    
    $stmt->close();
  } 
  
  public function update_entrance_application() {
    global $conn;
    date_default_timezone_set('Asia/Manila'); // Correct timezone setting
    $response = array();
  
    // Variables
    $data = json_decode(file_get_contents("php://input"), true);
    $user_id = htmlspecialchars($_GET['uid'] ?? '');
    $scholarship_type_id = htmlspecialchars($_GET['stid'] ?? '');
    $type_id = htmlspecialchars($_GET['tid'] ?? '');
    $first_name = htmlspecialchars($data['first_name'] ?? '');
    $middle_name = htmlspecialchars($data['middle_name'] ?? '');
    $last_name = htmlspecialchars($data['last_name'] ?? '');
    $suffix = htmlspecialchars($data['suffix'] ?? '');
    $academic_year = htmlspecialchars($data['academic_year'] ?? '');
    $year_level = htmlspecialchars($data['year_level'] ?? '');
    $semester = htmlspecialchars($data['semester'] ?? '');
    $program = htmlspecialchars($data['program'] ?? '');
    $email_address = htmlspecialchars($data['email_address'] ?? '');
    $contact_number = htmlspecialchars($data['contact_number'] ?? '');
    $honors_received = htmlspecialchars($data['honors_received'] ?? '');
    $general_weighted_average = htmlspecialchars($data['general_weighted_average'] ?? '');
  
    // Validate security
    $security_key = new SecurityKey($conn);
    $security_response = $security_key->validateBearerToken();
  
    if ($security_response['status'] === 'error') {
      echo json_encode($security_response);
      return;
    }
  
    if ($security_response['role'] !== 'student' && $security_response['role'] !== 'authorized_user') {
      echo json_encode(['status' => 'error', 'message' => 'Unauthorized access']);
      return;
    }
  
    // Validation checks
    $required_fields = [
      'uid' => $user_id,
      'stid' => $scholarship_type_id,
      'tid' => $type_id,
      'first_name' => $first_name,
      'middle_name' => $middle_name,
      'last_name' => $last_name,
      'academic_year' => $academic_year,
      'year_level' => $year_level,
      'semester' => $semester,
      'program' => $program,
      'email_address' => $email_address,
      'contact_number' => $contact_number,
      'honors_received' => $honors_received,
      'general_weighted_average' => $general_weighted_average
    ];
  
    foreach ($required_fields as $field => $value) {
      if (empty($value)) {
        $response['status'] = 'error';
        $response['message'] = ucfirst(str_replace('_', ' ', $field)) . ' cannot be empty';
        echo json_encode($response);
        return;
      }
    }
  
    // Check if user_id exists in the users table
    $check_user_id = $conn->prepare("SELECT user_id FROM users WHERE user_id = ?");
    $check_user_id->bind_param("s", $user_id);
    $check_user_id->execute();
    $check_user_id->store_result();
  
    if ($check_user_id->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid user ID';
      echo json_encode($response);
      $check_user_id->close();
      return;
    }
    $check_user_id->close();
  
    // Check if scholarship_type_id exists in the scholarship_types table
    $check_scholarship_type = $conn->prepare("SELECT scholarship_type_id FROM scholarship_types WHERE scholarship_type_id = ?");
    $check_scholarship_type->bind_param("s", $scholarship_type_id);
    $check_scholarship_type->execute();
    $check_scholarship_type->store_result();
  
    if ($check_scholarship_type->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid scholarship type ID';
      echo json_encode($response);
      $check_scholarship_type->close();
      return;
    }
    $check_scholarship_type->close();
  
    // Check if type_id exists in the type table and if the archive field allows submission
    $check_type_id = $conn->prepare("SELECT type_id, archive FROM type WHERE type_id = ?");
    $check_type_id->bind_param("s", $type_id);
    $check_type_id->execute();
    $check_type_id->store_result();
    $check_type_id->bind_result($db_type_id, $archive);
  
    if ($check_type_id->num_rows === 0) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid type ID';
      echo json_encode($response);
      $check_type_id->close();
      return;
    }
  
    $check_type_id->fetch();
  
    if (!empty($archive) || $archive === 'hide') {
      $response['status'] = 'error';
      $response['message'] = 'Application submission is closed';
      echo json_encode($response);
      $check_type_id->close();
      return;
    }
  
    $check_type_id->close();
  
    // Update data in `forms`
    $stmt = $conn->prepare("UPDATE forms SET
                              scholarship_type_id = ?,
                              type_id = ?,
                              first_name = ?,
                              middle_name = ?,
                              last_name = ?,
                              suffix = ?,
                              academic_year = ?,
                              year_level = ?,
                              semester = ?,
                              program = ?,
                              email_address = ?,
                              contact_number = ?,
                              honors_received = ?,
                              general_weighted_average = ?
                            WHERE user_id = ?");
  
    $stmt->bind_param(
      "sssssssssssssss",
      $scholarship_type_id,
      $type_id,
      $first_name,
      $middle_name,
      $last_name,
      $suffix,
      $academic_year,
      $year_level,
      $semester,
      $program,
      $email_address,
      $contact_number,
      $honors_received,
      $general_weighted_average,
      $user_id
    );
  
    if ($stmt->execute()) {
      $response['status'] = 'success';
      $response['message'] = 'Entrance application updated successfully';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Failed to update entrance application';
      echo json_encode($response);
      return;
    }
  
    $stmt->close();
  }  
}

?>