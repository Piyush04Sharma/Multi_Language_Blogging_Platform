<?php
$link = mysqli_connect("localhost", "root", "", "multiblog");

if ($link === false) {
    die("Error: Could not connect. " . mysqli_connect_error());
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST['userName'] ?? '';
    $rating = $_POST['rating'] ?? '';
    $review = $_POST['userReview'] ?? '';

    $sql = "INSERT INTO rating_review (name, rating, review) VALUES (?, ?, ?)";

    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "sss", $name, $rating, $review);

        if (mysqli_stmt_execute($stmt)) {
            echo "Success";
        } else {
            echo "Execute error: " . mysqli_stmt_error($stmt);
        }

        mysqli_stmt_close($stmt);
    } else {
        echo "Prepare error: " . mysqli_error($link);
    }
}

mysqli_close($link);
?>
