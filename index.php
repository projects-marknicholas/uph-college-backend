<?php
use myPHPnotes\Microsoft\Auth;

require 'config.php';
require 'router.php';

// Controllers
require 'controllers/auth.php';
require 'controllers/admin.php';
require 'controllers/dashboard.php';
require 'controllers/student.php';
require 'vendor/autoload.php';

// Security
require 'key.php';
require 'activity.php';
require 'email.php';

// Initialize Router
$router = new Router();

// Post Requests
$router->post('/api/auth/register', 'AuthController@register');
$router->post('/api/auth/login', 'AuthController@login');
$router->post('/api/auth/forgot-password', 'AuthController@forgot_password');
$router->post('/api/auth/reset-password', 'AuthController@reset_password');
$router->get('/api/auth/google', 'AuthController@google_auth');
$router->get('/api/auth/microsoft-signin', 'AuthController@microsoft_signin');
$router->get('/api/auth/microsoft', 'AuthController@microsoft_auth');

$router->post('/api/v1/scholarship-type', 'AdminController@add_scholarship_type');
$router->post('/api/v1/type', 'AdminController@add_type');
$router->post('/api/v1/applications', 'AdminController@add_application');
$router->post('/api/v1/student/entrance-application', 'StudentController@insert_entrance_application');

// Get Requests
$router->get('/api/auth/sk', 'AuthController@security_key');
$router->get('/api/v1/scholarship-type', 'AdminController@get_scholarship_type');
$router->get('/api/v1/type', 'AdminController@get_type');
$router->get('/api/v1/scholarship-type-category', 'AdminController@get_scholarship_type_by_category');
$router->get('/api/v1/account-approval', 'AdminController@get_users');
$router->get('/api/v1/active-accounts', 'AdminController@get_active_users');
$router->get('/api/v1/account-approval-search', 'AdminController@search_users');
$router->get('/api/v1/active-accounts-search', 'AdminController@search_active_users');
$router->get('/api/v1/accounts', 'AdminController@get_user_accounts');
$router->get('/api/v1/applications', 'AdminController@get_applications');
$router->get('/api/v1/applications-search', 'AdminController@search_applications');
$router->get('/api/v1/scholars-search', 'AdminController@search_scholars');
$router->get('/api/v1/scholars', 'AdminController@get_scholars');
$router->get('/api/v1/activities', 'DashboardController@get_activities');
$router->get('/api/v1/totals', 'DashboardController@get_totals');
$router->get('/api/v1/scholar-analytics', 'DashboardController@scholar_analytics');
$router->get('/api/v1/student/account', 'StudentController@get_account_by_id');
$router->get('/api/v1/student/applications', 'StudentController@get_applications');
$router->get('/api/v1/student/scholarship-types', 'StudentController@get_scholarship_types');
$router->get('/api/v1/student/type', 'StudentController@get_type_by_stid');

// Put Requests
$router->put('/api/v1/scholarship-type', 'AdminController@update_scholarship_type');
$router->put('/api/v1/archive', 'AdminController@hide_scholarship_archive');
$router->put('/api/v1/type', 'AdminController@update_type');
$router->put('/api/v1/account-approval', 'AdminController@update_user_role');
$router->put('/api/v1/active-accounts', 'AdminController@update_active_users');
$router->put('/api/v1/applications', 'AdminController@update_application');
$router->put('/api/v1/student/account', 'StudentController@update_account');
$router->put('/api/v1/student/entrance-application', 'StudentController@update_entrance_application');

// Delete Requests
$router->delete('/api/v1/scholarship-type', 'AdminController@delete_scholarship_type');
$router->delete('/api/v1/account-approval', 'AdminController@delete_user');
$router->delete('/api/v1/accounts', 'AdminController@delete_user_accounts');
$router->delete('/api/v1/applications', 'AdminController@delete_application');
$router->delete('/api/v1/scholars', 'AdminController@delete_scholar');

// Dispatch the request
$router->dispatch();
?>
