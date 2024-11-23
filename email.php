<?php

class SendEmail {

  private $apiKey = "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";
  private $url = "https://api.brevo.com/v3/smtp/email";

  // Function to send email using Brevo API
  public function sendMail($senderName, $senderEmail, $recipientEmail, $subject, $body) {
    $data = [
      "sender" => ["name" => $senderName, "email" => $senderEmail],
      "to" => [["email" => $recipientEmail]],
      "subject" => $subject,
      "htmlContent" => $body
    ];

    // Initialize cURL
    $ch = curl_init($this->url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
      "Content-Type: application/json",
      "api-key: $this->apiKey"
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));

    // Execute the request
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // Check if the email was sent successfully
    if ($httpCode === 201) {
      return "Email sent successfully!";
    } else {
      return "Failed to send email. Response: $response";
    }
  }
}

?>