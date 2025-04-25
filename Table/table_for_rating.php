<?php
$link = mysqli_connect("localhost", "root", "", "multiblog");

if ($link === false) {
    die("error: could not connect. " . mysqli_connect_error());
}

$sql = "CREATE TABLE rating_review (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    rating INT,
    review TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)"; // <-- Close the SQL string properly

if (mysqli_query($link, $sql)) {
    echo "Table created successfully";
} else {
    echo "Error: could not execute $sql. " . mysqli_error($link);
}

mysqli_close($link);
?>
