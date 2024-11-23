<?php
class DashboardController {
  public function get_activities() {
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
  
    $year = isset($_GET['year']) ? (int)$_GET['year'] : date('Y');
    $sem = isset($_GET['sem']) ? $_GET['sem'] : '1st';
  
    $start_month = ($sem === '1st') ? 9 : 2; // September for 1st semester, February for 2nd semester
    $end_month = ($sem === '1st') ? 12 : 5; // January for 1st semester, May for 2nd semester
  
    $stmt = $conn->prepare("
      SELECT 
        a.user_id, 
        a.action, 
        CONCAT(u.first_name, ' ', u.last_name, ' ', a.title) AS title, 
        a.description, 
        a.created_at 
      FROM activities a
      JOIN users u ON a.user_id = u.user_id
      WHERE YEAR(a.created_at) = ? AND MONTH(a.created_at) BETWEEN ? AND ?
      ORDER BY a.created_at DESC
      LIMIT ?, ?
    ");
    $stmt->bind_param("iiiii", $year, $start_month, $end_month, $offset, $records_per_page);
    $stmt->execute();
    $result = $stmt->get_result();
  
    $total_stmt = $conn->prepare("
      SELECT COUNT(*) as total 
      FROM activities a 
      JOIN users u ON a.user_id = u.user_id
      WHERE YEAR(a.created_at) = ? AND MONTH(a.created_at) BETWEEN ? AND ?
    ");
    $total_stmt->bind_param("iii", $year, $start_month, $end_month);
    $total_stmt->execute();
    $total_result = $total_stmt->get_result();
    $total_row = $total_result->fetch_assoc();
    $total_records = $total_row['total'];
  
    if ($result->num_rows > 0) {
      $activities = array();
  
      while ($row = $result->fetch_assoc()) {
        $activities[] = $row;
      }
  
      $response['status'] = 'success';
      $response['data'] = $activities;
      $response['pagination'] = array(
        'current_page' => $page,
        'records_per_page' => $records_per_page,
        'total_records' => $total_records,
        'total_pages' => ceil($total_records / $records_per_page)
      );
    } else {
      $response['status'] = 'error';
      $response['message'] = 'No activities found';
    }
  
    $stmt->close();
    $total_stmt->close();
    echo json_encode($response);
  }    

  public function get_totals() {
    global $conn;
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
  
    // Get year and semester from parameters
    $year = isset($_GET['year']) ? (int)$_GET['year'] : date('Y');
    $sem = isset($_GET['sem']) ? $_GET['sem'] : '1st';
  
    // Determine the months based on semester
    $start_month = ($sem === '1st') ? 9 : 2; // September for 1st semester, February for 2nd semester
    $end_month = ($sem === '1st') ? 12 : 5; // January for 1st semester, May for 2nd semester

    // Get total pending applications
    $pending_stmt = $conn->prepare("
      SELECT COUNT(*) as total_applications 
      FROM applications 
      WHERE status = 'pending' AND YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $pending_stmt->bind_param("iii", $year, $start_month, $end_month);
    $pending_stmt->execute();
    $pending_result = $pending_stmt->get_result();
    $pending_row = $pending_result->fetch_assoc();
  
    // Get total accepted applications
    $accepted_stmt = $conn->prepare("
      SELECT COUNT(*) as total_applications 
      FROM applications 
      WHERE status = 'accepted' AND YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $accepted_stmt->bind_param("iii", $year, $start_month, $end_month);
    $accepted_stmt->execute();
    $accepted_result = $accepted_stmt->get_result();
    $accepted_row = $accepted_result->fetch_assoc();
  
    // Get total roles in users table
    $roles_stmt = $conn->prepare("
      SELECT COUNT(DISTINCT role) as total_roles 
      FROM users
      WHERE YEAR(joined_at) = ? AND MONTH(joined_at) BETWEEN ? AND ?
    ");
    $roles_stmt->bind_param("iii", $year, $start_month, $end_month);
    $roles_stmt->execute();
    $roles_result = $roles_stmt->get_result();
    $roles_row = $roles_result->fetch_assoc();
  
    // Get total scholarship types
    $scholarship_types_stmt = $conn->prepare("
      SELECT COUNT(*) as total_scholarship_types 
      FROM scholarship_types
      WHERE YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $scholarship_types_stmt->bind_param("iii", $year, $start_month, $end_month);
    $scholarship_types_stmt->execute();
    $scholarship_types_result = $scholarship_types_stmt->get_result();
    $scholarship_types_row = $scholarship_types_result->fetch_assoc();
  
    // Calculate totals for the last semester based on the current semester
    if ($sem === '1st') {
      $last_sem_year = $year - 1; // Previous year for 2nd semester
      $last_sem_start_month = 2; // February
      $last_sem_end_month = 5; // May
    } else {
      $last_sem_year = $year; // Same year for 1st semester
      $last_sem_start_month = 9; // September
      $last_sem_end_month = 12; // January
    }

    // Get total pending applications for last semester
    $last_pending_stmt = $conn->prepare("
      SELECT COUNT(*) as total_applications 
      FROM applications 
      WHERE status = 'pending' AND YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $last_pending_stmt->bind_param("iii", $last_sem_year, $last_sem_start_month, $last_sem_end_month);
    $last_pending_stmt->execute();
    $last_pending_result = $last_pending_stmt->get_result();
    $last_pending_row = $last_pending_result->fetch_assoc();

    // Get total accepted applications for last semester
    $last_accepted_stmt = $conn->prepare("
      SELECT COUNT(*) as total_applications 
      FROM applications 
      WHERE status = 'accepted' AND YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $last_accepted_stmt->bind_param("iii", $last_sem_year, $last_sem_start_month, $last_sem_end_month);
    $last_accepted_stmt->execute();
    $last_accepted_result = $last_accepted_stmt->get_result();
    $last_accepted_row = $last_accepted_result->fetch_assoc();
  
    // Get total roles for last semester
    $last_roles_stmt = $conn->prepare("
      SELECT COUNT(DISTINCT role) as total_roles 
      FROM users
      WHERE YEAR(joined_at) = ? AND MONTH(joined_at) BETWEEN ? AND ?
    ");
    $last_roles_stmt->bind_param("iii", $last_sem_year, $last_sem_start_month, $last_sem_end_month);
    $last_roles_stmt->execute();
    $last_roles_result = $last_roles_stmt->get_result();
    $last_roles_row = $last_roles_result->fetch_assoc();
  
    // Get total scholarship types for last semester
    $last_scholarship_types_stmt = $conn->prepare("
      SELECT COUNT(*) as total_scholarship_types 
      FROM scholarship_types
      WHERE YEAR(created_at) = ? AND MONTH(created_at) BETWEEN ? AND ?
    ");
    $last_scholarship_types_stmt->bind_param("iii", $last_sem_year, $last_sem_start_month, $last_sem_end_month);
    $last_scholarship_types_stmt->execute();
    $last_scholarship_types_result = $last_scholarship_types_stmt->get_result();
    $last_scholarship_types_row = $last_scholarship_types_result->fetch_assoc();

    // Calculate percentage changes
    $pending_percentage_change = $this->calculate_percentage_change($pending_row['total_applications'], $last_pending_row['total_applications']);
    $accepted_percentage_change = $this->calculate_percentage_change($accepted_row['total_applications'], $last_accepted_row['total_applications']);
    $roles_percentage_change = $this->calculate_percentage_change($roles_row['total_roles'], $last_roles_row['total_roles']);
    $scholarship_types_percentage_change = $this->calculate_percentage_change($scholarship_types_row['total_scholarship_types'], $last_scholarship_types_row['total_scholarship_types']);

    // Calculate specific increase or decrease
    $pending_difference = $pending_row['total_applications'] - $last_pending_row['total_applications'];
    $accepted_difference = $accepted_row['total_applications'] - $last_accepted_row['total_applications'];
    $roles_difference = $roles_row['total_roles'] - $last_roles_row['total_roles'];
    $scholarship_types_difference = $scholarship_types_row['total_scholarship_types'] - $last_scholarship_types_row['total_scholarship_types'];

    $response['status'] = 'success';
    $response['data'] = array(
      'total_pending_applications' => $pending_row['total_applications'],
      'pending_percentage_change' => $pending_percentage_change,
      'pending_difference' => $pending_difference,
      'total_accepted_applications' => $accepted_row['total_applications'],
      'accepted_percentage_change' => $accepted_percentage_change,
      'accepted_difference' => $accepted_difference,
      'total_roles' => $roles_row['total_roles'],
      'roles_percentage_change' => $roles_percentage_change,
      'roles_difference' => $roles_difference,
      'total_scholarship_types' => $scholarship_types_row['total_scholarship_types'],
      'scholarship_types_percentage_change' => $scholarship_types_percentage_change,
      'scholarship_types_difference' => $scholarship_types_difference
    );
  
    $pending_stmt->close();
    $accepted_stmt->close();
    $roles_stmt->close();
    $scholarship_types_stmt->close();
    $last_pending_stmt->close();
    $last_accepted_stmt->close();
    $last_roles_stmt->close();
    $last_scholarship_types_stmt->close();
    echo json_encode($response);
  }

  private function calculate_percentage_change($current, $previous) {
    if ($previous == 0) {
      return $current > 0 ? 100 : ($current < 0 ? -100 : 0);
    }
    return (($current - $previous) / abs($previous)) * 100;
  }

  public function scholar_analytics() {
		global $conn;
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

		// Get year and semester from parameters or use defaults
		$year = isset($_GET['year']) ? (int)$_GET['year'] : date('Y');
		$sem = isset($_GET['sem']) ? $_GET['sem'] : '1st';

		// Determine start and end months based on the semester
		if ($sem === '1st') {
			$start_month = 9; // September
			$end_month = 12;  // December
		} else {
			$start_month = 2;  // February
			$end_month = 5;    // May
		}

		// Initialize an array for the months
		$months = array(
			"january" => 0,
			"february" => 0,
			"march" => 0,
			"april" => 0,
			"may" => 0,
			"june" => 0,
			"july" => 0,
			"august" => 0,
			"september" => 0,
			"october" => 0,
			"november" => 0,
			"december" => 0
		);

		// Prepare and execute the query to get the count of accepted applications for each month
		for ($month = 1; $month <= 12; $month++) {
			// Only count for months within the specified semester
			if (($sem === '1st' && $month >= $start_month && $month <= $end_month) ||
				($sem === '2nd' && $month >= $start_month && $month <= $end_month)) {
				
				$stmt = $conn->prepare("
					SELECT COUNT(*) as total_accepted 
					FROM applications 
					WHERE status = 'accepted' AND YEAR(created_at) = ? AND MONTH(created_at) = ?
				");
				$stmt->bind_param("ii", $year, $month);
				$stmt->execute();
				$result = $stmt->get_result();
				$row = $result->fetch_assoc();
				$stmt->close();

				// Map the month number to the corresponding month name in the response
				$month_name = strtolower(date('F', mktime(0, 0, 0, $month, 1))); // e.g., "January"
				$months[$month_name] = $row['total_accepted'];
			}
		}

		// Prepare the success response
		$response['status'] = 'success';
		$response['data'] = $months;

		echo json_encode($response);
	}
}
?>