<?php
    $link = mysqli_connect("localhost", "root", "");
    if($link === false)
    {
        die("error: could not connect." . mysqli_connect_error());
    }
    $sql = "create database multiblog";
    if (mysqli_query ($link, $sql))
    {
        echo "database created successfully";
    }
    else
    {
        echo "error : could not able to execute $sql." . mysqli_error($link);
    }
    mysqli_close($link);
?>