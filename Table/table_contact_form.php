<?php
    $link = mysqli_connect("localhost", "root", "", "multiblog");
    if($link === false)
    {
        die("error: could not connect. " .mysqli_connect_error());
    }
    $sql = "create table contact_form( name varchar(50) not null,
    email varchar(50) not null, 
    subject varchar(50), 
    message varchar(300) not null)";
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