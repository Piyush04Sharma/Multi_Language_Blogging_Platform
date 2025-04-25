<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];

    

    $to = $email;
    $subject = "Thanks for Subscribing!";
    $message = "Thank you for subscribing! You'll now receive updates from us.";
    $from = "amandeepkumar0807@gmail.com";
    $headers = "From: $from";

    if(mail($to, $subject, $message, $headers)) {
        // Save to database if needed
        $link = mysqli_connect("localhost", "root", "", "multiblog");
        if($link === false){
            die("ERROR: Could not connect. " . mysqli_connect_error());
        }

        $sql = "INSERT INTO subscribers (email) VALUES (?)";
        if($stmt = mysqli_prepare($link, $sql)){
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
        }
        mysqli_close($link);

        header("location: index.php");
        exit();
    } else {
        echo "Mail not sent.";
    }
}
?>
