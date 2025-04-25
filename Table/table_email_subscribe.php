<?php
    $link = mysqli_connect("localhost", "root", "", "multiblog");
    if($link === false)
    {
        die("error: could not connect. " .mysqli_connect_error());
    }
    $sql = "create table subscribers( email varchar(50) not null)";
    if(mysqli_query ($link, $sql))
    {
        echo "table created successfully";
    }
    else
    {
        echo "error: could not able to execute $sql" . mysqli_error($link);
    }
    mysqli_close($link);
?>